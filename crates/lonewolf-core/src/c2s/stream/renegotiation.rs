// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::io;
use std::net::Shutdown;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use compio::net::TcpStream;
use futures_util::io::{AsyncRead, AsyncWrite};
use rustls::ProtocolVersion;
use socket2::SockRef;

pub(super) struct RecordGuard<R> {
    io: R,
    socket: TcpStream,
    header: [u8; 5],
    header_used: usize,
    remaining: usize,
    yield_boundary: bool,
    mode: Mode,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Accepting,
    Tls12,
    Passthrough,
    Rejected,
}

#[derive(Debug)]
struct RenegotiationDetected;

impl fmt::Display for RenegotiationDetected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TLS renegotiation is unsupported")
    }
}

impl std::error::Error for RenegotiationDetected {}

fn rejection() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, RenegotiationDetected)
}

pub(super) fn is_detected(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|error| error.is::<RenegotiationDetected>())
}

impl<R> RecordGuard<R> {
    pub(super) fn new(io: R, socket: TcpStream) -> Self {
        Self {
            io,
            socket,
            header: [0; 5],
            header_used: 0,
            remaining: 0,
            yield_boundary: false,
            mode: Mode::Accepting,
        }
    }

    pub(super) fn handshake_complete(&mut self, version: Option<ProtocolVersion>) {
        if self.mode == Mode::Accepting {
            self.mode = if version == Some(ProtocolVersion::TLSv1_2) {
                Mode::Tls12
            } else {
                Mode::Passthrough
            };
            self.yield_boundary = false;
        }
    }

    fn record_complete(&mut self) {
        self.header_used = 0;
        self.yield_boundary = self.mode == Mode::Accepting;
    }

    fn reject(&mut self) -> io::Error {
        self.mode = Mode::Rejected;
        let _ = SockRef::from(&self.socket).shutdown(Shutdown::Both);
        rejection()
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for RecordGuard<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.mode == Mode::Rejected {
            return Poll::Ready(Err(rejection()));
        }
        if output.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.mode == Mode::Passthrough {
            return Pin::new(&mut this.io).poll_read(cx, output);
        }
        if this.yield_boundary {
            this.yield_boundary = false;
            // The adapter must check Finished before it reads the next record.
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let reading_header = this.remaining == 0;
        let limit = if reading_header {
            5 - this.header_used
        } else {
            this.remaining
        };
        let limit = output.len().min(limit);
        let count = ready!(Pin::new(&mut this.io).poll_read(cx, &mut output[..limit]))?;
        if count == 0 {
            return Poll::Ready(Ok(0));
        }
        if reading_header {
            if this.header_used == 0 && this.mode == Mode::Tls12 && output[0] == 22 {
                return Poll::Ready(Err(this.reject()));
            }
            this.header[this.header_used..this.header_used + count]
                .copy_from_slice(&output[..count]);
            this.header_used += count;
            if this.header_used == 5 {
                this.remaining = usize::from(u16::from_be_bytes([this.header[3], this.header[4]]));
                if this.remaining == 0 {
                    this.record_complete();
                }
            }
        } else {
            this.remaining -= count;
            if this.remaining == 0 {
                this.record_complete();
            }
        }
        Poll::Ready(Ok(count))
    }
}

impl<R: AsyncWrite + Unpin> AsyncWrite for RecordGuard<R> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.mode == Mode::Rejected {
            Poll::Ready(Err(rejection()))
        } else {
            Pin::new(&mut this.io).poll_write(cx, input)
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.mode == Mode::Rejected {
            Poll::Ready(Err(rejection()))
        } else {
            Pin::new(&mut this.io).poll_flush(cx)
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.mode == Mode::Rejected {
            Poll::Ready(Err(rejection()))
        } else {
            Pin::new(&mut this.io).poll_close(cx)
        }
    }
}

#[cfg(test)]
mod tests;
