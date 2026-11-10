// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::io::{AsyncRead, AsyncWrite};

pub(crate) trait TrafficObserver {
    /// For futures I/O, skips empty reads and yields after each positive read.
    const COOPERATIVE_READS: bool = false;
    fn received(&self, bytes: usize);
    fn sent(&self, bytes: usize);
}

pub(crate) struct ObservedIo<T, O: TrafficObserver> {
    inner: T,
    observer: O,
    yield_read: bool,
}

impl<T, O: TrafficObserver> ObservedIo<T, O> {
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

impl<T: AsyncRead + Unpin, O: TrafficObserver + Unpin> AsyncRead for ObservedIo<T, O> {
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

impl<T: AsyncWrite + Unpin, O: TrafficObserver + Unpin> AsyncWrite for ObservedIo<T, O> {
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

impl<T: compio::io::AsyncRead, O: TrafficObserver> compio::io::AsyncRead for ObservedIo<T, O> {
    async fn read<B: compio::buf::IoBufMut>(&mut self, buf: B) -> compio::BufResult<usize, B> {
        let result = self.inner.read(buf).await;
        if let Ok(count) = &result.0 {
            self.observer.received(*count);
        }
        result
    }

    async fn read_vectored<B: compio::buf::IoVectoredBufMut>(
        &mut self,
        buf: B,
    ) -> compio::BufResult<usize, B> {
        let result = self.inner.read_vectored(buf).await;
        if let Ok(count) = &result.0 {
            self.observer.received(*count);
        }
        result
    }
}

impl<T: compio::io::AsyncWrite, O: TrafficObserver> compio::io::AsyncWrite for ObservedIo<T, O> {
    async fn write<B: compio::buf::IoBuf>(&mut self, buf: B) -> compio::BufResult<usize, B> {
        let result = self.inner.write(buf).await;
        if let Ok(count) = &result.0 {
            self.observer.sent(*count);
        }
        result
    }

    async fn write_vectored<B: compio::buf::IoVectoredBuf>(
        &mut self,
        buf: B,
    ) -> compio::BufResult<usize, B> {
        let result = self.inner.write_vectored(buf).await;
        if let Ok(count) = &result.0 {
            self.observer.sent(*count);
        }
        result
    }

    async fn flush(&mut self) -> io::Result<()> {
        self.inner.flush().await
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.inner.shutdown().await
    }
}

impl<T: compio::io::util::Splittable, O: TrafficObserver + Clone> compio::io::util::Splittable
    for ObservedIo<T, O>
{
    type ReadHalf = ObservedIo<T::ReadHalf, O>;
    type WriteHalf = ObservedIo<T::WriteHalf, O>;

    fn split(self) -> (Self::ReadHalf, Self::WriteHalf) {
        let (read, write) = self.inner.split();
        (
            ObservedIo::new(read, self.observer.clone()),
            ObservedIo::new(write, self.observer),
        )
    }
}

#[cfg(test)]
#[path = "tests/traffic.rs"]
mod tests;
