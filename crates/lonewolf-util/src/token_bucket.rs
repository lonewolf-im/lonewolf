// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

const NANOS_PER_SECOND: u128 = 1_000_000_000;

pub struct TokenBucket {
    tokens: usize,
    remainder: u128,
    updated_at: Instant,
}

impl TokenBucket {
    /// Starts with a full burst at the supplied time.
    #[inline]
    pub fn new(burst: NonZeroUsize, now: Instant) -> Self {
        Self {
            tokens: burst.get(),
            remainder: 0,
            updated_at: now,
        }
    }

    /// A full burst discards fractional credit.
    /// Backward time preserves the refill clock.
    #[inline]
    pub fn replenish(&mut self, per_second: NonZeroUsize, burst: NonZeroUsize, now: Instant) {
        let elapsed = now.saturating_duration_since(self.updated_at);
        let credit = elapsed
            .as_nanos()
            .saturating_mul(per_second.get() as u128)
            .saturating_add(self.remainder);
        let replenished = (credit / NANOS_PER_SECOND).min(burst.get() as u128) as usize;
        self.tokens = self.tokens.saturating_add(replenished).min(burst.get());
        self.remainder = if self.tokens == burst.get() {
            0
        } else {
            credit % NANOS_PER_SECOND
        };
        self.updated_at = self.updated_at.max(now);
    }

    #[inline]
    pub fn available(&self) -> usize {
        self.tokens
    }

    /// Panics if `amount` exceeds the available tokens.
    #[inline]
    pub fn consume(&mut self, amount: usize) {
        assert!(amount <= self.tokens);
        self.tokens -= amount;
    }

    /// Returns the delay for one token, even when tokens are available.
    #[inline]
    pub fn refill_delay(&self, per_second: NonZeroUsize) -> Duration {
        let remaining = NANOS_PER_SECOND - self.remainder;
        let nanos = remaining.div_ceil(per_second.get() as u128).max(1);
        Duration::from_nanos(nanos as u64)
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    type TestResult = Result<(), Box<dyn Error>>;

    #[test]
    fn fractional_credit_carries_until_the_exact_refill_boundary() -> TestResult {
        let rate = NonZeroUsize::new(3).ok_or("invalid rate")?;
        let burst = NonZeroUsize::new(2).ok_or("invalid burst")?;
        let start = Instant::now();
        let mut bucket = TokenBucket::new(burst, start);
        assert_eq!(bucket.available(), 2);
        bucket.consume(2);
        bucket.replenish(rate, burst, start + Duration::from_millis(100));
        assert_eq!(bucket.available(), 0);
        assert_eq!(bucket.refill_delay(rate), Duration::from_nanos(233_333_334));
        bucket.replenish(rate, burst, start + Duration::from_nanos(333_333_333));
        assert_eq!(bucket.available(), 0);
        assert_eq!(bucket.refill_delay(rate), Duration::from_nanos(1));
        bucket.replenish(rate, burst, start + Duration::from_nanos(333_333_334));
        assert_eq!(bucket.available(), 1);
        assert_eq!(bucket.remainder, 2);
        bucket.consume(1);
        bucket.replenish(rate, burst, start + Duration::from_nanos(666_666_666));
        assert_eq!(bucket.available(), 0);
        bucket.replenish(rate, burst, start + Duration::from_nanos(666_666_667));
        assert_eq!(bucket.available(), 1);
        Ok(())
    }

    #[test]
    fn idle_credit_caps_at_the_burst_and_discards_fractional_overflow() -> TestResult {
        let rate = NonZeroUsize::new(3).ok_or("invalid rate")?;
        let burst = NonZeroUsize::new(2).ok_or("invalid burst")?;
        let start = Instant::now();
        let mut bucket = TokenBucket::new(burst, start);
        bucket.consume(2);
        bucket.replenish(rate, burst, start + Duration::from_millis(400));
        assert_eq!(bucket.available(), 1);
        assert_eq!(bucket.remainder, 200_000_000);
        bucket.replenish(rate, burst, start + Duration::from_millis(10_100));
        assert_eq!(bucket.available(), 2);
        assert_eq!(bucket.remainder, 0);
        bucket.consume(2);
        assert_eq!(bucket.refill_delay(rate), Duration::from_nanos(333_333_334));
        Ok(())
    }

    #[test]
    fn maximum_rates_and_bursts_do_not_overflow_or_require_burst_above_rate() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(NonZeroUsize::MAX, start);
        bucket.replenish(
            NonZeroUsize::MAX,
            NonZeroUsize::MAX,
            start + Duration::from_secs(3600),
        );
        assert_eq!(bucket.available(), usize::MAX);
        bucket.consume(usize::MAX);
        bucket.replenish(
            NonZeroUsize::MAX,
            NonZeroUsize::MAX,
            start + Duration::from_secs(3601),
        );
        assert_eq!(bucket.available(), usize::MAX);
        bucket.consume(1);
        assert_eq!(bucket.available(), usize::MAX - 1);

        let mut bucket = TokenBucket::new(NonZeroUsize::MIN, start);
        bucket.consume(1);
        assert_eq!(
            bucket.refill_delay(NonZeroUsize::MAX),
            Duration::from_nanos(1)
        );
        bucket.replenish(
            NonZeroUsize::MAX,
            NonZeroUsize::MIN,
            start + Duration::from_nanos(1),
        );
        assert_eq!(bucket.available(), 1);
    }

    #[test]
    fn backward_time_preserves_the_refill_clock_and_fractional_credit() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(NonZeroUsize::MIN, start);
        bucket.consume(1);
        bucket.replenish(
            NonZeroUsize::MIN,
            NonZeroUsize::MIN,
            start + Duration::from_millis(500),
        );
        bucket.replenish(NonZeroUsize::MIN, NonZeroUsize::MIN, start);
        assert_eq!(bucket.available(), 0);
        assert_eq!(bucket.updated_at, start + Duration::from_millis(500));
        assert_eq!(bucket.remainder, NANOS_PER_SECOND / 2);
        bucket.replenish(
            NonZeroUsize::MIN,
            NonZeroUsize::MIN,
            start + Duration::from_secs(1),
        );
        assert_eq!(bucket.available(), 1);
    }

    #[test]
    #[should_panic]
    fn consuming_more_than_available_panics() {
        TokenBucket::new(NonZeroUsize::MIN, Instant::now()).consume(2);
    }
}
