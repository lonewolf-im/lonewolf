// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use futures_util::io::{AsyncRead, AsyncWrite};

use crate::s2s::metrics::{Direction, S2sMetrics};

pub(in crate::s2s) trait IdleClock {
    fn now(&self) -> Instant;
    fn sleep_until(&self, deadline: Instant) -> impl Future<Output = ()>;
}

pub(in crate::s2s) struct SystemIdleClock;
impl IdleClock for SystemIdleClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    async fn sleep_until(&self, deadline: Instant) {
        compio::time::sleep_until(deadline).await;
    }
}

#[derive(Clone)]
pub(crate) struct ConnectionActivity(Rc<Cell<Instant>>);
impl ConnectionActivity {
    pub(crate) fn new(at: Instant) -> Self {
        Self(Rc::new(Cell::new(at)))
    }
    pub(crate) fn record(&self, at: Instant) {
        self.0.set(self.0.get().max(at));
    }
    pub(crate) fn last(&self) -> Instant {
        self.0.get()
    }
}

pub(crate) struct CountingIo<T> {
    inner: T,
    metrics: Arc<S2sMetrics>,
    direction: Direction,
    activity: ConnectionActivity,
    yield_read: bool,
}

impl<T> CountingIo<T> {
    pub(crate) fn activity(&self) -> ConnectionActivity {
        self.activity.clone()
    }

    pub(crate) fn new(inner: T, metrics: Arc<S2sMetrics>, direction: Direction) -> Self {
        Self {
            inner,
            metrics,
            direction,
            activity: ConnectionActivity::new(Instant::now()),
            yield_read: false,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for CountingIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if output.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.yield_read {
            self.yield_read = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let result = Pin::new(&mut self.inner).poll_read(cx, output);
        if let Poll::Ready(Ok(count)) = result {
            self.metrics.bytes(self.direction, count as u64, 0);
            if count > 0 {
                self.activity.record(Instant::now());
                self.yield_read = true;
            }
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
            if count > 0 {
                self.activity.record(Instant::now());
            }
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
            metrics(),
            Direction::Outbound,
        );
        let old = Instant::now() - std::time::Duration::from_secs(1);
        io.activity = ConnectionActivity::new(old);
        let activity = io.activity();
        let mut output = [0; 8];
        assert!(matches!(
            Pin::new(&mut io).poll_read(&mut cx, &mut output),
            Poll::Ready(Ok(2))
        ));
        let after_read = activity.last();
        assert!(after_read > old);
        io.inner.result = Poll::Ready(Ok(3));
        assert!(matches!(
            Pin::new(&mut io).poll_read(&mut cx, &mut []),
            Poll::Ready(Ok(0))
        ));
        assert!(io.yield_read);
        assert!(
            Pin::new(&mut io)
                .poll_read(&mut cx, &mut output)
                .is_pending()
        );
        assert_eq!(activity.last(), after_read);
        assert_eq!(wake.0.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert!(matches!(io.inner.result, Poll::Ready(Ok(3))));
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
            io.inner.result = result;
            let before = activity.last();
            let _ = Pin::new(&mut io).poll_read(&mut cx, &mut output);
            assert!(!io.yield_read);
            assert_eq!(activity.last(), before);
        }
        io.activity = ConnectionActivity::new(old);
        let activity = io.activity();
        io.inner.result = Poll::Ready(Ok(1));
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
            io.inner.result = result;
            let _ = Pin::new(&mut io).poll_write(&mut cx, b"x");
            assert_eq!(activity.last(), before);
        }
        let _ = Pin::new(&mut io).poll_flush(&mut cx);
        let _ = Pin::new(&mut io).poll_close(&mut cx);
        assert_eq!(activity.last(), before);
        assert_eq!(io.inner.flushes, 1);
        assert_eq!(io.inner.closes, 1);
        assert!(!io.yield_read);
        Ok(())
    }
}

#[cfg(test)]
pub(in crate::s2s) mod test_support {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::future::poll_fn;
    use std::task::Waker;
    use std::time::Duration;

    pub(in crate::s2s) struct Clock {
        now: Cell<Instant>,
        deadline: Cell<Option<Instant>>,
        waker: RefCell<Option<Waker>>,
    }
    impl Clock {
        pub(in crate::s2s) fn new() -> Self {
            Self {
                now: Cell::new(Instant::now()),
                deadline: Cell::new(None),
                waker: RefCell::new(None),
            }
        }
        pub(in crate::s2s) fn advance(&self, duration: Duration) {
            self.now.set(self.now.get() + duration);
            if let Some(waker) = self.waker.borrow_mut().take() {
                waker.wake();
            }
        }
    }
    impl IdleClock for Clock {
        fn now(&self) -> Instant {
            self.now.get()
        }
        async fn sleep_until(&self, deadline: Instant) {
            poll_fn(|cx| {
                self.deadline.set(Some(deadline));
                if self.now.get() >= deadline {
                    Poll::Ready(())
                } else {
                    *self.waker.borrow_mut() = Some(cx.waker().clone());
                    Poll::Pending
                }
            })
            .await;
        }
    }

    #[derive(Clone, Default)]
    pub(in crate::s2s) struct Fragments(Rc<RefCell<Input>>);
    #[derive(Default)]
    struct Input {
        bytes: VecDeque<Vec<u8>>,
        offset: usize,
        polls: usize,
        waker: Option<Waker>,
    }
    impl Fragments {
        pub(in crate::s2s) fn push(&self, bytes: &[u8]) {
            let mut state = self.0.borrow_mut();
            state.bytes.push_back(bytes.to_vec());
            if let Some(waker) = state.waker.take() {
                waker.wake();
            }
        }
        pub(in crate::s2s) fn polls(&self) -> usize {
            self.0.borrow().polls
        }
    }
    impl AsyncRead for Fragments {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            output: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let mut state = self.0.borrow_mut();
            state.polls += 1;
            let Some(bytes) = state.bytes.front() else {
                state.waker = Some(cx.waker().clone());
                return Poll::Pending;
            };
            let length = bytes.len();
            let count = output.len().min(length - state.offset);
            output[..count].copy_from_slice(&bytes[state.offset..state.offset + count]);
            state.offset += count;
            if state.offset == length {
                state.bytes.pop_front();
                state.offset = 0;
            }
            Poll::Ready(Ok(count))
        }
    }
}
