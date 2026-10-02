// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

const NANOS_PER_SECOND: u128 = 1_000_000_000;

pub(super) struct StanzaLimiter {
    per_second: usize,
    burst: usize,
    tokens: usize,
    remainder: u128,
    updated_at: Instant,
}

impl StanzaLimiter {
    pub(super) fn new(per_second: NonZeroUsize, burst: NonZeroUsize) -> Self {
        Self {
            per_second: per_second.get(),
            burst: burst.get(),
            tokens: burst.get(),
            remainder: 0,
            updated_at: Instant::now(),
        }
    }

    pub(super) async fn acquire(&mut self) {
        while !self.try_acquire(Instant::now()) {
            compio::time::sleep(self.refill_delay()).await;
        }
    }

    fn try_acquire(&mut self, now: Instant) -> bool {
        self.replenish(now);
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }

    fn replenish(&mut self, now: Instant) {
        let credit = now
            .saturating_duration_since(self.updated_at)
            .as_nanos()
            .saturating_mul(self.per_second as u128)
            .saturating_add(self.remainder);
        let replenished = (credit / NANOS_PER_SECOND).min(self.burst as u128) as usize;
        self.tokens = self.tokens.saturating_add(replenished).min(self.burst);
        self.remainder = if self.tokens == self.burst {
            0
        } else {
            credit % NANOS_PER_SECOND
        };
        self.updated_at = self.updated_at.max(now);
    }

    fn refill_delay(&self) -> Duration {
        let nanos = (NANOS_PER_SECOND - self.remainder)
            .div_ceil(self.per_second as u128)
            .max(1);
        Duration::from_nanos(nanos as u64)
    }
}

#[cfg(test)]
mod tests;
