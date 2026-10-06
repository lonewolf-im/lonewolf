// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::io;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Instant;

use tokio::io::{AsyncBufRead, AsyncRead, ReadBuf};

use crate::token_bucket::TokenBucket;

/// Starts with a full burst and uses the current Compio runtime for refill waits.
pub struct RateLimitedReader<R> {
    inner: R,
    state: RateLimitState,
}

/// Keeps one connection's XML rate allowance across transport upgrades.
pub struct RateLimitState {
    bytes_per_second: NonZeroUsize,
    burst_bytes: NonZeroUsize,
    bucket: TokenBucket,
    refill_wait: Option<Pin<Box<dyn Future<Output = ()>>>>,
}

impl<R> RateLimitedReader<R> {
    pub fn new(inner: R, bytes_per_second: NonZeroUsize, burst_bytes: NonZeroUsize) -> Self {
        Self {
            inner,
            state: RateLimitState {
                bytes_per_second,
                burst_bytes,
                bucket: TokenBucket::new(burst_bytes, Instant::now()),
                refill_wait: None,
            },
        }
    }

    pub fn from_state(inner: R, state: RateLimitState) -> Self {
        Self { inner, state }
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    pub fn into_inner(self) -> R {
        self.inner
    }

    pub fn into_state(self) -> RateLimitState {
        self.state
    }
}

impl<R: AsyncBufRead + Unpin> AsyncBufRead for RateLimitedReader<R> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        this.state.bucket.replenish(
            this.state.bytes_per_second,
            this.state.burst_bytes,
            Instant::now(),
        );
        while this.state.bucket.available() == 0 {
            let wait = this.state.bucket.refill_delay(this.state.bytes_per_second);
            let timer = this
                .state
                .refill_wait
                .get_or_insert_with(|| Box::pin(compio::time::sleep(wait)));
            ready!(timer.as_mut().poll(cx));
            this.state.refill_wait = None;
            this.state.bucket.replenish(
                this.state.bytes_per_second,
                this.state.burst_bytes,
                Instant::now(),
            );
        }
        this.state.refill_wait = None;
        let available = ready!(Pin::new(&mut this.inner).poll_fill_buf(cx))?;
        Poll::Ready(Ok(
            &available[..available.len().min(this.state.bucket.available())]
        ))
    }

    fn consume(self: Pin<&mut Self>, amount: usize) {
        let this = self.get_mut();
        this.state.bucket.consume(amount);
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
mod tests;
