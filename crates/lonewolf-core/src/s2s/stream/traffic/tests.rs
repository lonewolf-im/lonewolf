// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, Cursor};

use prometheus_client::registry::Registry;

use super::*;
use crate::xml_stream::traffic::CountingIo;
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
            S2sTrafficObserver::new(Arc::clone(&metrics), Direction::Inbound),
        );
        let mut buffer = [0; 3];
        assert_eq!(input.read(&mut buffer).await?, 3);
        assert_eq!(input.read(&mut buffer).await?, 2);
        assert_eq!(input.read(&mut buffer).await?, 0);
        assert_eq!(input.read(&mut []).await?, 0);
        let mut output = CountingIo::new(
            Vec::new(),
            S2sTrafficObserver::new(Arc::clone(&metrics), Direction::Inbound),
        );
        output.write_all(b"goodbye").await?;
        assert_eq!(output.write(&[]).await?, 0);
        output.flush().await?;
        output.close().await?;
        assert_eq!(*output.inner_mut(), b"goodbye");
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
        S2sTrafficObserver::new(Arc::clone(&metrics), Direction::Inbound),
    );
    let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
    let mut buffer = [0; 8];
    assert!(
        Pin::new(&mut io)
            .poll_read(&mut cx, &mut buffer)
            .is_pending()
    );
    assert!(Pin::new(&mut io).poll_write(&mut cx, &buffer).is_pending());
    io.inner_mut().result = Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
    assert!(matches!(
        Pin::new(&mut io).poll_read(&mut cx, &mut buffer),
        Poll::Ready(Err(_))
    ));
    io.inner_mut().result = Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
    assert!(matches!(
        Pin::new(&mut io).poll_write(&mut cx, &buffer),
        Poll::Ready(Err(_))
    ));
    io.inner_mut().result = Poll::Ready(Ok(2));
    assert!(matches!(
        Pin::new(&mut io).poll_read(&mut cx, &mut buffer),
        Poll::Ready(Ok(2))
    ));
    io.inner_mut().result = Poll::Ready(Ok(3));
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
    assert_eq!(io.inner_mut().flushes, 1);
    assert_eq!(io.inner_mut().closes, 1);
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
#[test]
fn physical_activity_and_read_cooperation_follow_only_successful_positive_io()
-> Result<(), Box<dyn std::error::Error>> {
    struct Wake(std::sync::atomic::AtomicUsize);
    impl futures_util::task::ArcWake for Wake {
        fn wake_by_ref(this: &Arc<Self>) {
            this.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    let wake = Arc::new(Wake(std::sync::atomic::AtomicUsize::new(0)));
    let waker = futures_util::task::waker_ref(&wake);
    let mut cx = Context::from_waker(&waker);
    let mut io = CountingIo::new(
        ControlledIo {
            result: Poll::Ready(Ok(2)),
            flushes: 0,
            closes: 0,
        },
        S2sTrafficObserver::new(metrics(), Direction::Outbound),
    );
    let old = Instant::now() - std::time::Duration::from_secs(1);
    io.observer_mut().activity = ConnectionActivity::new(old);
    let activity = io.observer().activity();
    let mut output = [0; 8];
    assert!(matches!(
        Pin::new(&mut io).poll_read(&mut cx, &mut output),
        Poll::Ready(Ok(2))
    ));
    let after_read = activity.last();
    assert!(after_read > old);
    io.inner_mut().result = Poll::Ready(Ok(3));
    assert!(matches!(
        Pin::new(&mut io).poll_read(&mut cx, &mut []),
        Poll::Ready(Ok(0))
    ));
    assert!(io.yields_read());
    assert!(
        Pin::new(&mut io)
            .poll_read(&mut cx, &mut output)
            .is_pending()
    );
    assert_eq!(activity.last(), after_read);
    assert_eq!(wake.0.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert!(matches!(io.inner_mut().result, Poll::Ready(Ok(3))));
    assert!(matches!(
        Pin::new(&mut io).poll_read(&mut cx, &mut output),
        Poll::Ready(Ok(3))
    ));
    assert!(
        Pin::new(&mut io)
            .poll_read(&mut cx, &mut output)
            .is_pending()
    );
    for result in [
        Poll::Ready(Ok(0)),
        Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        Poll::Pending,
    ] {
        io.inner_mut().result = result;
        let before = activity.last();
        let _ = Pin::new(&mut io).poll_read(&mut cx, &mut output);
        assert!(!io.yields_read());
        assert_eq!(activity.last(), before);
    }
    io.observer_mut().activity = ConnectionActivity::new(old);
    let activity = io.observer().activity();
    io.inner_mut().result = Poll::Ready(Ok(1));
    assert!(matches!(
        Pin::new(&mut io).poll_write(&mut cx, b"x"),
        Poll::Ready(Ok(1))
    ));
    assert!(activity.last() > old);
    let before = activity.last();
    for result in [
        Poll::Ready(Ok(0)),
        Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        Poll::Pending,
    ] {
        io.inner_mut().result = result;
        let _ = Pin::new(&mut io).poll_write(&mut cx, b"x");
        assert_eq!(activity.last(), before);
    }
    let _ = Pin::new(&mut io).poll_flush(&mut cx);
    let _ = Pin::new(&mut io).poll_close(&mut cx);
    assert_eq!(activity.last(), before);
    assert_eq!(io.inner_mut().flushes, 1);
    assert_eq!(io.inner_mut().closes, 1);
    assert!(!io.yields_read());
    Ok(())
}
