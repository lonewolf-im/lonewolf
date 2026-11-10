// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::future::{Future, poll_fn};
use std::num::NonZeroUsize;
use std::task::Poll;
use std::time::Instant;

use lonewolf_util::token_bucket::TokenBucket;

use super::reader::{ReadMode, ReadObserver};

pub(crate) struct StanzaLimiter {
    per_second: NonZeroUsize,
    burst: NonZeroUsize,
    bucket: TokenBucket,
}

impl StanzaLimiter {
    pub(crate) fn new(per_second: NonZeroUsize, burst: NonZeroUsize) -> Self {
        Self {
            per_second,
            burst,
            bucket: TokenBucket::new(burst, Instant::now()),
        }
    }

    pub(crate) fn available(&self) -> usize {
        self.bucket.available()
    }

    pub(crate) async fn acquire(&mut self, mode: &Cell<ReadMode>, observer: &impl ReadObserver) {
        let mut reported = false;
        loop {
            if mode.get() != ReadMode::Open || self.try_acquire(Instant::now()) {
                break;
            }
            let mut wait = std::pin::pin!(compio::time::sleep(
                self.bucket.refill_delay(self.per_second)
            ));
            poll_fn(|cx| {
                if mode.get() != ReadMode::Open {
                    Poll::Ready(())
                } else {
                    let result = wait.as_mut().poll(cx);
                    if result.is_pending() && !reported {
                        observer.rate_limited();
                        reported = true;
                    }
                    result
                }
            })
            .await;
        }
    }

    fn try_acquire(&mut self, now: Instant) -> bool {
        self.bucket.replenish(self.per_second, self.burst, now);
        if self.available() == 0 {
            return false;
        }
        self.bucket.consume(1);
        true
    }
}

#[cfg(test)]
#[path = "tests/limiter.rs"]
mod tests;
