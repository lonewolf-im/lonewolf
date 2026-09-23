// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::io;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufRead, AsyncRead, ReadBuf};

const NANOS_PER_SECOND: u128 = 1_000_000_000;

/// Starts with a full burst and uses the current Compio runtime for refill waits.
pub struct RateLimitedReader<R> {
    inner: R,
    bytes_per_second: usize,
    burst_bytes: usize,
    tokens: usize,
    remainder: u128,
    updated_at: Instant,
    refill_wait: Option<Pin<Box<dyn Future<Output = ()>>>>,
}

impl<R> RateLimitedReader<R> {
    pub fn new(inner: R, bytes_per_second: NonZeroUsize, burst_bytes: NonZeroUsize) -> Self {
        Self {
            inner,
            bytes_per_second: bytes_per_second.get(),
            burst_bytes: burst_bytes.get(),
            tokens: burst_bytes.get(),
            remainder: 0,
            updated_at: Instant::now(),
            refill_wait: None,
        }
    }

    fn replenish(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.updated_at);
        let credit = elapsed
            .as_nanos()
            .saturating_mul(self.bytes_per_second as u128)
            .saturating_add(self.remainder);
        let replenished = (credit / NANOS_PER_SECOND).min(self.burst_bytes as u128) as usize;
        self.tokens = self
            .tokens
            .saturating_add(replenished)
            .min(self.burst_bytes);
        self.remainder = if self.tokens == self.burst_bytes {
            0
        } else {
            credit % NANOS_PER_SECOND
        };
        self.updated_at = self.updated_at.max(now);
    }

    fn refill_delay(&self) -> Duration {
        let remaining = NANOS_PER_SECOND - self.remainder;
        let rate = self.bytes_per_second as u128;
        let nanos = remaining.div_ceil(rate).max(1);
        Duration::from_nanos(nanos as u64)
    }
}

impl<R: AsyncBufRead + Unpin> AsyncBufRead for RateLimitedReader<R> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        this.replenish(Instant::now());
        while this.tokens == 0 {
            let wait = this.refill_delay();
            let timer = this
                .refill_wait
                .get_or_insert_with(|| Box::pin(compio::time::sleep(wait)));
            ready!(timer.as_mut().poll(cx));
            this.refill_wait = None;
            this.replenish(Instant::now());
        }
        this.refill_wait = None;
        let available = ready!(Pin::new(&mut this.inner).poll_fill_buf(cx))?;
        Poll::Ready(Ok(&available[..available.len().min(this.tokens)]))
    }

    fn consume(self: Pin<&mut Self>, amount: usize) {
        let this = self.get_mut();
        assert!(amount <= this.tokens);
        this.tokens -= amount;
        Pin::new(&mut this.inner).consume(amount);
    }
}

impl<R: AsyncBufRead + Unpin> AsyncRead for RateLimitedReader<R> {
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

#[cfg(test)]
#[path = "../tests/rate_limited_reader/reader.rs"]
mod tests;
