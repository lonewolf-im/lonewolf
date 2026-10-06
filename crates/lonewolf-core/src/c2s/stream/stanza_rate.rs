// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroUsize;
use std::time::Instant;

use lonewolf_util::token_bucket::TokenBucket;

pub(super) struct StanzaLimiter {
    per_second: NonZeroUsize,
    burst: NonZeroUsize,
    bucket: TokenBucket,
}

impl StanzaLimiter {
    pub(super) fn new(per_second: NonZeroUsize, burst: NonZeroUsize) -> Self {
        Self {
            per_second,
            burst,
            bucket: TokenBucket::new(burst, Instant::now()),
        }
    }

    pub(super) async fn acquire(&mut self) {
        while !self.try_acquire(Instant::now()) {
            compio::time::sleep(self.bucket.refill_delay(self.per_second)).await;
        }
    }

    fn try_acquire(&mut self, now: Instant) -> bool {
        self.bucket.replenish(self.per_second, self.burst, now);
        if self.bucket.available() == 0 {
            return false;
        }
        self.bucket.consume(1);
        true
    }
}

#[cfg(test)]
mod tests;
