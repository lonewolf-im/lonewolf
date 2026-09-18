// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncBufRead, AsyncRead, ReadBuf};

pub(super) struct LimitedReader<R> {
    pub(super) inner: R,
    remaining: usize,
    limit: usize,
    skip_whitespace: bool,
    pub(super) whitespace_skipped: bool,
    opening_bracket: bool,
}

#[derive(Debug)]
pub(super) struct InputLimit(pub(super) usize);

impl fmt::Display for InputLimit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XML input exceeds the byte limit")
    }
}

impl std::error::Error for InputLimit {}

impl<R> LimitedReader<R> {
    pub(super) fn new(inner: R, limit: usize) -> Self {
        Self {
            inner,
            remaining: limit,
            limit,
            skip_whitespace: true,
            whitespace_skipped: false,
            opening_bracket: false,
        }
    }

    pub(super) fn reset(&mut self, limit: usize) {
        self.remaining = limit;
        self.limit = limit;
        self.skip_whitespace = true;
        self.whitespace_skipped = false;
        self.opening_bracket = false;
    }

    pub(super) fn skip_whitespace(&mut self) {
        self.skip_whitespace = true;
    }
}

impl<R: AsyncBufRead + Unpin> AsyncBufRead for LimitedReader<R> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        let mut skipped = 0;
        while this.skip_whitespace {
            let available = ready!(Pin::new(&mut this.inner).poll_fill_buf(cx))?;
            let whitespace = available
                .iter()
                .take_while(|byte| is_whitespace(**byte))
                .count();
            if whitespace == 0 {
                this.skip_whitespace = false;
                break;
            }
            Pin::new(&mut this.inner).consume(whitespace);
            this.whitespace_skipped = true;
            skipped += 1;
            if skipped == 64 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
        if this.remaining == 0 && !(this.limit == 1 && this.opening_bracket) {
            return Poll::Ready(Err(io::Error::other(InputLimit(this.limit))));
        }
        let available = ready!(Pin::new(&mut this.inner).poll_fill_buf(cx))?;
        let consumed = this.limit - this.remaining;
        if consumed == 0 {
            this.opening_bracket = available.first() == Some(&b'<');
        }
        if (consumed == 0 && available.starts_with(b"</"))
            || (consumed == 1 && this.opening_bracket && available.first() == Some(&b'/'))
        {
            // The stream footer has its own budget, independent of stanza size.
            this.limit = super::MAX_STREAM_HEADER_BYTES;
            this.remaining = this.limit - consumed;
        }
        if this.remaining == 0 {
            return Poll::Ready(Err(io::Error::other(InputLimit(this.limit))));
        }
        Poll::Ready(Ok(&available[..available.len().min(this.remaining)]))
    }

    fn consume(self: Pin<&mut Self>, amount: usize) {
        let this = self.get_mut();
        this.remaining -= amount;
        Pin::new(&mut this.inner).consume(amount);
    }
}

impl<R: AsyncBufRead + Unpin> AsyncRead for LimitedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let available = ready!(self.as_mut().poll_fill_buf(cx))?;
        let amount = available.len().min(output.remaining());
        output.put_slice(&available[..amount]);
        self.consume(amount);
        Poll::Ready(Ok(()))
    }
}

pub(super) fn is_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}
