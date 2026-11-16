//! Shared blocking-reader machinery for OS transports: pure `std`, zero
//! crates. A dedicated thread owns the read handle and does blocking reads;
//! [`Transport::exchange_timeout`] waits on it with `recv_timeout`.
//!
//! Used by `hw::linux` / `hw::macos` / `hw::windows` — one tested core,
//! three thin OS shims. HID report length stays a caller parameter (all
//! wallet devices here use 64-byte reports).

use std::io::Read;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::error::{Error, Result};

use alloc::vec::Vec;

enum ReaderReq {
    Read,
    Stop,
}

enum ReaderResp {
    Report(Vec<u8>),
    IoError,
}

/// Blocking-reader endpoint. Send [`ReaderReq::Read`], wait for one report.
/// Created by [`spawn_report_reader`]; shut down with [`ReportReader::stop`].
#[derive(Debug)]
pub(crate) struct ReportReader {
    req_tx: Sender<ReaderReq>,
    resp_rx: Receiver<ReaderResp>,
}

/// Spawn the reader thread over any blocking `Read`: each `Read` request
/// yields exactly `report_len` bytes (or an I/O error). Returns the endpoint
/// plus the thread handle (the owner keeps it alive; on drop it asks the
/// thread to exit and detaches — a thread parked in a timed-out read exits
/// when the device finally answers).
pub(crate) fn spawn_report_reader<R: Read + Send + 'static>(
    r: R,
    report_len: usize,
) -> (ReportReader, JoinHandle<()>) {
    let (req_tx, req_rx) = mpsc::channel::<ReaderReq>();
    let (resp_tx, resp_rx) = mpsc::channel::<ReaderResp>();
    let handle = std::thread::spawn(move || {
        let mut r = r;
        // Stop, or owner dropped: exit.
        while let Ok(ReaderReq::Read) = req_rx.recv() {
            let mut buf = alloc::vec![0u8; report_len];
            let resp = match r.read_exact(&mut buf) {
                Ok(()) => ReaderResp::Report(buf),
                Err(_) => ReaderResp::IoError,
            };
            if resp_tx.send(resp).is_err() {
                break;
            }
        }
    });
    (ReportReader { req_tx, resp_rx }, handle)
}

impl ReportReader {
    pub(crate) fn read_report(&self, timeout: Duration) -> Result<Vec<u8>> {
        self.req_tx
            .send(ReaderReq::Read)
            .map_err(|_| Error::TransportDisconnected)?;
        match self.resp_rx.recv_timeout(timeout) {
            Ok(ReaderResp::Report(b)) => Ok(b),
            Ok(ReaderResp::IoError) => Err(Error::TransportRead),
            Err(RecvTimeoutError::Timeout) => Err(Error::TransportTimeout),
            Err(RecvTimeoutError::Disconnected) => Err(Error::TransportDisconnected),
        }
    }

    pub(crate) fn stop(&self) {
        let _ = self.req_tx.send(ReaderReq::Stop);
    }
}

/// Write one report with a leading report-ID byte (`0x00` for devices without
/// numbered reports): the hidraw/Windows-HID wire format for `report`.
/// Generic over `Write` so tests exercise it over TCP loopback.
pub(crate) fn write_report_with_id<W: std::io::Write>(w: &mut W, report: &[u8]) -> Result<()> {
    let mut wire = Vec::with_capacity(report.len() + 1);
    wire.push(0x00);
    wire.extend_from_slice(report);
    w.write_all(&wire).map_err(|_| Error::TransportWrite)?;
    w.flush().map_err(|_| Error::TransportWrite)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::net::{TcpListener, TcpStream};

    fn pair() -> (TcpStream, TcpStream) {
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = ln.local_addr().unwrap().port();
        let a = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let (b, _) = ln.accept().unwrap();
        (a, b)
    }

    #[test]
    fn reply_arrives_before_deadline() {
        let (a, mut b) = pair();
        let (reader, _h) = spawn_report_reader(a, 4);
        b.write_all(b"ping").unwrap();
        b.flush().unwrap();
        let got = reader.read_report(Duration::from_secs(5)).unwrap();
        assert_eq!(got, b"ping");
        reader.stop();
    }

    #[test]
    fn silence_is_timeout_not_disconnect() {
        let (a, _b) = pair();
        let (reader, _h) = spawn_report_reader(a, 4);
        assert_eq!(
            reader.read_report(Duration::from_millis(50)).unwrap_err(),
            Error::TransportTimeout
        );
        reader.stop();
    }

    #[test]
    fn dead_reader_is_disconnect() {
        let (a, _b) = pair();
        let (reader, h) = spawn_report_reader(a, 4);
        reader.stop();
        h.join().unwrap();
        // Once the thread exited, reads report a dead channel.
        assert_eq!(
            reader.read_report(Duration::from_millis(50)).unwrap_err(),
            Error::TransportDisconnected
        );
    }
}
