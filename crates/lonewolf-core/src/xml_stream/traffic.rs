// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::io::{AsyncRead, AsyncWrite};

pub(crate) trait TrafficObserver {
    /// Skips empty reads and yields once after each successful nonempty read.
    const COOPERATIVE_READS: bool = false;
    fn received(&self, bytes: usize);
    fn sent(&self, bytes: usize);
}

pub(crate) struct CountingIo<T, O: TrafficObserver> {
    inner: T,
    observer: O,
    yield_read: bool,
}

impl<T, O: TrafficObserver> CountingIo<T, O> {
    pub(crate) fn new(inner: T, observer: O) -> Self {
        Self {
            inner,
            observer,
            yield_read: false,
        }
    }

    pub(crate) fn observer(&self) -> &O {
        &self.observer
    }

    #[cfg(test)]
    pub(crate) fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    #[cfg(test)]
    pub(crate) fn observer_mut(&mut self) -> &mut O {
        &mut self.observer
    }

    #[cfg(test)]
    pub(crate) fn yields_read(&self) -> bool {
        self.yield_read
    }
}

impl<T: AsyncRead + Unpin, O: TrafficObserver + Unpin> AsyncRead for CountingIo<T, O> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if O::COOPERATIVE_READS {
            if output.is_empty() {
                return Poll::Ready(Ok(0));
            }
            if self.yield_read {
                self.yield_read = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
        let result = Pin::new(&mut self.inner).poll_read(cx, output);
        if let Poll::Ready(Ok(count)) = result {
            self.observer.received(count);
            if O::COOPERATIVE_READS && count > 0 {
                self.yield_read = true;
            }
        }
        result
    }
}

impl<T: AsyncWrite + Unpin, O: TrafficObserver + Unpin> AsyncWrite for CountingIo<T, O> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, input);
        if let Poll::Ready(Ok(count)) = result {
            self.observer.sent(count);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}
