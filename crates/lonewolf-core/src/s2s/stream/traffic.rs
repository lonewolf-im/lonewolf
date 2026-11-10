// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::future::Future;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;

use crate::s2s::metrics::{Direction, S2sMetrics};
use crate::xml_stream::traffic::TrafficObserver;

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

pub(crate) struct S2sTrafficObserver {
    metrics: Arc<S2sMetrics>,
    direction: Direction,
    activity: ConnectionActivity,
}

impl S2sTrafficObserver {
    pub(crate) fn new(metrics: Arc<S2sMetrics>, direction: Direction) -> Self {
        Self {
            metrics,
            direction,
            activity: ConnectionActivity::new(Instant::now()),
        }
    }

    pub(crate) fn activity(&self) -> ConnectionActivity {
        self.activity.clone()
    }
}

impl TrafficObserver for S2sTrafficObserver {
    const COOPERATIVE_READS: bool = true;

    fn received(&self, bytes: usize) {
        self.metrics.bytes(self.direction, bytes as u64, 0);
        if bytes > 0 {
            self.activity.record(Instant::now());
        }
    }

    fn sent(&self, bytes: usize) {
        self.metrics.bytes(self.direction, 0, bytes as u64);
        if bytes > 0 {
            self.activity.record(Instant::now());
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(in crate::s2s) mod test_support {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::future::poll_fn;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    use futures_util::io::AsyncRead;

    use super::*;

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
