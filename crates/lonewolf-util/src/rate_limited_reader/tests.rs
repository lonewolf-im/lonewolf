// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use compio::runtime::Runtime;
use futures_util::future::poll_fn;
use futures_util::poll;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncReadExt, ReadBuf};

use super::*;

#[derive(Clone)]
pub(super) struct Clock(std::rc::Rc<ClockState>);

struct ClockState {
    now: std::cell::Cell<Instant>,
    waiter: std::cell::RefCell<Option<(Instant, std::task::Waker)>>,
}

impl Clock {
    fn new() -> Self {
        Self(std::rc::Rc::new(ClockState {
            now: std::cell::Cell::new(Instant::now()),
            waiter: std::cell::RefCell::new(None),
        }))
    }

    pub(super) fn now(&self) -> Instant {
        self.0.now.get()
    }

    fn advance(&self, elapsed: Duration) {
        self.0.now.set(self.now() + elapsed);
        let mut waiter = self.0.waiter.borrow_mut();
        if let Some((_, waker)) = waiter.take_if(|(deadline, _)| self.now() >= *deadline) {
            drop(waiter);
            waker.wake();
        }
    }

    pub(super) fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()>>> {
        let clock = self.clone();
        let deadline = self.now() + duration;
        Box::pin(poll_fn(move |context| {
            if clock.now() >= deadline {
                Poll::Ready(())
            } else {
                *clock.0.waiter.borrow_mut() = Some((deadline, context.waker().clone()));
                Poll::Pending
            }
        }))
    }

    fn reader<'a>(
        &self,
        bytes: &'a [u8],
        rate: usize,
        burst: usize,
    ) -> Result<RateLimitedReader<SliceReader<'a>>, Box<dyn Error>> {
        let rate = NonZeroUsize::new(rate).ok_or("invalid rate")?;
        let burst = NonZeroUsize::new(burst).ok_or("invalid burst")?;
        let mut reader = RateLimitedReader::new(SliceReader { bytes }, rate, burst);
        reader.state.bucket = TokenBucket::new(burst, self.now());
        reader.state.clock = Some(self.clone());
        Ok(reader)
    }
}

#[derive(Default)]
struct WakeCount(std::sync::atomic::AtomicUsize);

impl std::task::Wake for WakeCount {
    fn wake(self: std::sync::Arc<Self>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

struct SliceReader<'a> {
    bytes: &'a [u8],
}

impl AsyncBufRead for SliceReader<'_> {
    fn poll_fill_buf(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        Poll::Ready(Ok(self.get_mut().bytes))
    }

    fn consume(self: Pin<&mut Self>, amount: usize) {
        let this = self.get_mut();
        this.bytes = &this.bytes[amount..];
    }
}

impl AsyncRead for SliceReader<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let available = match self.as_mut().poll_fill_buf(cx) {
            Poll::Ready(Ok(available)) => available,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        };
        let amount = available.len().min(output.remaining());
        output.put_slice(&available[..amount]);
        self.consume(amount);
        Poll::Ready(Ok(()))
    }
}

#[test]
fn burst_then_refill_paces_all_bytes() -> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        let clock = Clock::new();
        let mut reader = clock.reader(b"abcde", 20, 3)?;
        let mut first = [0; 3];
        reader.read_exact(&mut first).await?;
        assert_eq!(&first, b"abc");
        let wakes = std::sync::Arc::new(WakeCount::default());
        let waker = std::task::Waker::from(wakes.clone());
        let mut context = Context::from_waker(&waker);
        assert!(
            Pin::new(&mut reader)
                .poll_fill_buf(&mut context)
                .is_pending()
        );
        clock.advance(Duration::from_millis(49));
        assert_eq!(wakes.0.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert!(
            Pin::new(&mut reader)
                .poll_fill_buf(&mut context)
                .is_pending()
        );
        clock.advance(Duration::from_millis(1));
        assert_eq!(wakes.0.load(std::sync::atomic::Ordering::Relaxed), 1);
        let mut fourth = [0; 1];
        assert_eq!(reader.read_exact(&mut fourth).await?, 1);
        assert_eq!(&fourth, b"d");
        let mut fifth = [0; 1];
        let mut reading = std::pin::pin!(reader.read_exact(&mut fifth));
        assert!(poll!(reading.as_mut()).is_pending());
        clock.advance(Duration::from_millis(50));
        assert_eq!(reading.await?, 1);
        assert_eq!(&fifth, b"e");
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn transport_upgrade_keeps_rate_allowance() -> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        let clock = Clock::new();
        let mut before = clock.reader(b"ab", 10, 2)?;
        let mut initial = [0; 2];
        before.read_exact(&mut initial).await?;
        let mut after =
            RateLimitedReader::from_state(SliceReader { bytes: b"c" }, before.into_state());
        let mut next = [0; 1];
        let mut reading = std::pin::pin!(after.read_exact(&mut next));
        assert!(poll!(reading.as_mut()).is_pending());
        clock.advance(Duration::from_millis(99));
        assert!(poll!(reading.as_mut()).is_pending());
        clock.advance(Duration::from_millis(1));
        assert_eq!(reading.await?, 1);
        assert_eq!(&next, b"c");
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn transport_upgrade_keeps_an_already_pending_refill_timer() -> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        let clock = Clock::new();
        let mut before = clock.reader(b"ab", 2, 1)?;
        let mut initial = [0; 1];
        before.read_exact(&mut initial).await?;
        assert_eq!(&initial, b"a");
        poll_fn(|cx| {
            assert!(Pin::new(&mut before).poll_fill_buf(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let timer = before
            .state
            .refill_wait
            .as_ref()
            .ok_or("missing pending timer")?
            .as_ref()
            .get_ref() as *const dyn Future<Output = ()>;
        let delay = before
            .state
            .bucket
            .refill_delay(before.state.bytes_per_second);
        let state = before.into_state();
        assert_eq!(state.bucket.available(), 0);
        let mut after = RateLimitedReader::from_state(SliceReader { bytes: b"c" }, state);
        assert_eq!(after.state.bucket.available(), 0);
        assert_eq!(
            after
                .state
                .bucket
                .refill_delay(after.state.bytes_per_second),
            delay
        );
        assert!(std::ptr::eq(
            timer,
            after
                .state
                .refill_wait
                .as_ref()
                .ok_or("missing transferred timer")?
                .as_ref()
                .get_ref()
        ));
        let mut next = [0; 1];
        let mut reading = std::pin::pin!(after.read_exact(&mut next));
        assert!(poll!(reading.as_mut()).is_pending());
        clock.advance(Duration::from_millis(499));
        assert!(poll!(reading.as_mut()).is_pending());
        clock.advance(Duration::from_millis(1));
        assert_eq!(reading.await?, 1);
        assert_eq!(&next, b"c");
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
#[should_panic]
fn consuming_more_than_the_reader_allowance_panics() {
    let mut reader = RateLimitedReader::new(
        SliceReader { bytes: b"ab" },
        NonZeroUsize::MIN,
        NonZeroUsize::MIN,
    );
    Pin::new(&mut reader).consume(2);
}

#[derive(Default)]
struct Throttles(std::sync::atomic::AtomicUsize);

impl RateLimitObserver for Throttles {
    fn on_throttle(&self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[test]
fn observer_reports_own_wait_once_across_cancellation_and_transport_transfer()
-> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        let clock = Clock::new();
        let observer = Arc::new(Throttles::default());
        let mut reader = clock.reader(b"abc", 10, 1)?.with_observer(observer.clone());
        let mut byte = [0];
        reader.read_exact(&mut byte).await?;
        for _ in 0..3 {
            assert!(poll!(std::pin::pin!(reader.read_exact(&mut byte))).is_pending());
        }
        assert_eq!(observer.0.load(std::sync::atomic::Ordering::Relaxed), 1);
        let (_, state) = reader.into_parts();
        let mut reader = RateLimitedReader::from_state(SliceReader { bytes: b"de" }, state);
        assert!(poll!(std::pin::pin!(reader.read_exact(&mut byte))).is_pending());
        assert_eq!(observer.0.load(std::sync::atomic::Ordering::Relaxed), 1);
        clock.advance(Duration::from_millis(100));
        reader.read_exact(&mut byte).await?;
        assert_eq!(byte, *b"d");
        assert!(poll!(std::pin::pin!(reader.read_exact(&mut byte))).is_pending());
        assert_eq!(observer.0.load(std::sync::atomic::Ordering::Relaxed), 2);
        Ok(())
    })
}

#[test]
fn observer_does_not_report_transport_pending() -> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        let observer = Arc::new(Throttles::default());
        let (input, _output) = tokio::io::duplex(16);
        let mut reader = RateLimitedReader::new(
            tokio::io::BufReader::new(input),
            NonZeroUsize::MIN,
            NonZeroUsize::MIN,
        )
        .with_observer(observer.clone());
        let mut byte = [0];
        for _ in 0..3 {
            assert!(poll!(std::pin::pin!(reader.read_exact(&mut byte))).is_pending());
        }
        assert_eq!(observer.0.load(std::sync::atomic::Ordering::Relaxed), 0);
        Ok(())
    })
}
