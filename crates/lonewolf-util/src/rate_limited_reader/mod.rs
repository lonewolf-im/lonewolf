// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::io;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Instant;

use tokio::io::{AsyncBufRead, AsyncRead, ReadBuf};

use crate::token_bucket::TokenBucket;

pub trait RateLimitObserver: Send + Sync {
    /// Called once per refill wait that blocks a read.
    fn on_throttle(&self);
}

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
    observer: Option<Arc<dyn RateLimitObserver>>,
    wait_reported: bool,
    refill_wait: Option<Pin<Box<dyn Future<Output = ()>>>>,
    #[cfg(test)]
    clock: Option<tests::Clock>,
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
                observer: None,
                wait_reported: false,
                #[cfg(test)]
                clock: None,
            },
        }
    }

    pub fn with_observer(mut self, observer: Arc<dyn RateLimitObserver>) -> Self {
        self.state.observer = Some(observer);
        self
    }

    pub fn into_parts(self) -> (R, RateLimitState) {
        (self.inner, self.state)
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

impl RateLimitState {
    fn now(&self) -> Instant {
        #[cfg(test)]
        if let Some(clock) = &self.clock {
            return clock.now();
        }
        Instant::now()
    }
}

impl<R: AsyncBufRead + Unpin> AsyncBufRead for RateLimitedReader<R> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        let now = this.state.now();
        this.state
            .bucket
            .replenish(this.state.bytes_per_second, this.state.burst_bytes, now);
        while this.state.bucket.available() == 0 {
            let wait = this.state.bucket.refill_delay(this.state.bytes_per_second);
            let timer = this.state.refill_wait.get_or_insert_with(|| {
                #[cfg(test)]
                if let Some(clock) = &this.state.clock {
                    return clock.sleep(wait);
                }
                Box::pin(compio::time::sleep(wait))
            });
            if timer.as_mut().poll(cx).is_pending() {
                if !this.state.wait_reported {
                    if let Some(observer) = &this.state.observer {
                        observer.on_throttle();
                    }
                    this.state.wait_reported = true;
                }
                return Poll::Pending;
            }
            this.state.refill_wait = None;
            let now = this.state.now();
            this.state
                .bucket
                .replenish(this.state.bytes_per_second, this.state.burst_bytes, now);
        }
        this.state.refill_wait = None;
        this.state.wait_reported = false;
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
