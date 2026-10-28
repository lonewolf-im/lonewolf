// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::io::{AsyncRead, AsyncWrite};

use crate::s2s::metrics::{Direction, S2sMetrics};

pub(crate) struct CountingIo<T> {
    inner: T,
    metrics: Arc<S2sMetrics>,
    direction: Direction,
}

impl<T> CountingIo<T> {
    pub(crate) fn new(inner: T, metrics: Arc<S2sMetrics>, direction: Direction) -> Self {
        Self {
            inner,
            metrics,
            direction,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for CountingIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_read(cx, output);
        if let Poll::Ready(Ok(count)) = result {
            self.metrics.bytes(self.direction, count as u64, 0);
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for CountingIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, input);
        if let Poll::Ready(Ok(count)) = result {
            self.metrics.bytes(self.direction, 0, count as u64);
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

#[cfg(test)]
mod tests {
    use futures_util::io::{AsyncReadExt as _, AsyncWriteExt as _, Cursor};

    use super::*;
    use prometheus_client::registry::Registry;
    fn metrics() -> Arc<S2sMetrics> {
        S2sMetrics::new(1)
    }
    fn render(metrics: &Arc<S2sMetrics>) -> Result<String, Box<dyn std::error::Error>> {
        let mut registry = Registry::default();
        metrics.register(registry.sub_registry_with_prefix("lonewolf"));
        let mut body = String::new();
        prometheus_client::encoding::text::encode(&mut body, &registry)?;
        Ok(body)
    }

    #[test]
    fn reads_and_writes_are_counted() -> Result<(), Box<dyn std::error::Error>> {
        compio::runtime::Runtime::new()?.block_on(async {
            let metrics = metrics();
            let mut input = CountingIo::new(
                Cursor::new(b"hello"),
                Arc::clone(&metrics),
                Direction::Inbound,
            );
            let mut buffer = [0; 3];
            assert_eq!(input.read(&mut buffer).await?, 3);
            assert_eq!(input.read(&mut buffer).await?, 2);
            assert_eq!(input.read(&mut buffer).await?, 0);
            assert_eq!(input.read(&mut []).await?, 0);
            let mut output = CountingIo::new(Vec::new(), Arc::clone(&metrics), Direction::Inbound);
            output.write_all(b"goodbye").await?;
            assert_eq!(output.write(&[]).await?, 0);
            output.flush().await?;
            output.close().await?;
            assert_eq!(output.inner, b"goodbye");
            let body = render(&metrics)?;
            assert!(
                body.contains("lonewolf_s2s_received_bytes_total{direction=\"inbound\"} 5\n"),
                "{body}"
            );
            assert!(
                body.contains("lonewolf_s2s_sent_bytes_total{direction=\"inbound\"} 7\n"),
                "{body}"
            );
            Ok(())
        })
    }
    struct ControlledIo {
        result: Poll<io::Result<usize>>,
        flushes: usize,
        closes: usize,
    }

    impl AsyncRead for ControlledIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            output: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let result = std::mem::replace(&mut self.result, Poll::Pending);
            if let Poll::Ready(Ok(count)) = result {
                output[..count].fill(0);
            }
            result
        }
    }

    impl AsyncWrite for ControlledIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            std::mem::replace(&mut self.result, Poll::Pending)
        }

        fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.flushes += 1;
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        }

        fn poll_close(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.closes += 1;
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        }
    }

    #[test]
    fn pending_errors_and_partial_operations_preserve_actual_byte_counts()
    -> Result<(), Box<dyn std::error::Error>> {
        let metrics = metrics();
        let mut io = CountingIo::new(
            ControlledIo {
                result: Poll::Pending,
                flushes: 0,
                closes: 0,
            },
            Arc::clone(&metrics),
            Direction::Inbound,
        );
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
        let mut buffer = [0; 8];
        assert!(
            Pin::new(&mut io)
                .poll_read(&mut cx, &mut buffer)
                .is_pending()
        );
        assert!(Pin::new(&mut io).poll_write(&mut cx, &buffer).is_pending());
        io.inner.result = Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        assert!(matches!(
            Pin::new(&mut io).poll_read(&mut cx, &mut buffer),
            Poll::Ready(Err(_))
        ));
        io.inner.result = Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        assert!(matches!(
            Pin::new(&mut io).poll_write(&mut cx, &buffer),
            Poll::Ready(Err(_))
        ));
        io.inner.result = Poll::Ready(Ok(2));
        assert!(matches!(
            Pin::new(&mut io).poll_read(&mut cx, &mut buffer),
            Poll::Ready(Ok(2))
        ));
        io.inner.result = Poll::Ready(Ok(3));
        assert!(matches!(
            Pin::new(&mut io).poll_write(&mut cx, &buffer),
            Poll::Ready(Ok(3))
        ));
        assert!(matches!(
            Pin::new(&mut io).poll_flush(&mut cx),
            Poll::Ready(Err(_))
        ));
        assert!(matches!(
            Pin::new(&mut io).poll_close(&mut cx),
            Poll::Ready(Err(_))
        ));
        assert_eq!(io.inner.flushes, 1);
        assert_eq!(io.inner.closes, 1);
        let body = render(&metrics)?;
        assert!(
            body.contains("lonewolf_s2s_received_bytes_total{direction=\"inbound\"} 2\n"),
            "{body}"
        );
        assert!(
            body.contains("lonewolf_s2s_sent_bytes_total{direction=\"inbound\"} 3\n"),
            "{body}"
        );
        Ok(())
    }
}
