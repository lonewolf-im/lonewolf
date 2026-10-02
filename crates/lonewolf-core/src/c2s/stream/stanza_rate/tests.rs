// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use super::*;

type TestResult = Result<(), Box<dyn Error>>;

fn limiter(rate: usize, burst: usize) -> Result<StanzaLimiter, Box<dyn Error>> {
    Ok(StanzaLimiter::new(
        NonZeroUsize::new(rate).ok_or("invalid rate")?,
        NonZeroUsize::new(burst).ok_or("invalid burst")?,
    ))
}

#[test]
fn burst_is_full_and_fractional_credit_carries_until_the_exact_refill_boundary() -> TestResult {
    let mut bucket = limiter(3, 2)?;
    let start = bucket.updated_at;
    assert!(bucket.try_acquire(start));
    assert!(bucket.try_acquire(start));
    assert!(!bucket.try_acquire(start));
    assert!(!bucket.try_acquire(start + Duration::from_millis(100)));
    assert_eq!(bucket.refill_delay(), Duration::from_nanos(233_333_334));
    assert!(!bucket.try_acquire(start + Duration::from_nanos(333_333_333)));
    assert_eq!(bucket.refill_delay(), Duration::from_nanos(1));
    assert!(bucket.try_acquire(start + Duration::from_nanos(333_333_334)));
    assert_eq!(bucket.remainder, 2);
    assert!(!bucket.try_acquire(start + Duration::from_nanos(666_666_666)));
    assert!(bucket.try_acquire(start + Duration::from_nanos(666_666_667)));
    Ok(())
}

#[test]
fn an_idle_bucket_caps_credit_at_the_burst_and_discards_fractional_overflow() -> TestResult {
    let mut bucket = limiter(3, 2)?;
    let start = bucket.updated_at;
    assert!(bucket.try_acquire(start));
    assert!(bucket.try_acquire(start));
    let later = start + Duration::from_millis(10_100);
    bucket.replenish(later);
    assert_eq!(bucket.tokens, 2);
    assert_eq!(bucket.remainder, 0);
    assert!(bucket.try_acquire(later));
    assert!(bucket.try_acquire(later));
    assert!(!bucket.try_acquire(later));
    assert_eq!(bucket.refill_delay(), Duration::from_nanos(333_333_334));
    Ok(())
}

#[test]
fn maximum_rates_and_bursts_do_not_overflow_or_require_burst_above_rate() -> TestResult {
    let mut bucket = limiter(usize::MAX, usize::MAX)?;
    let start = bucket.updated_at;
    bucket.replenish(start + Duration::from_secs(3600));
    assert_eq!(bucket.tokens, usize::MAX);
    bucket.tokens = 0;
    assert!(bucket.try_acquire(start + Duration::from_secs(3601)));
    assert_eq!(bucket.tokens, usize::MAX - 1);

    let mut bucket = limiter(usize::MAX, 1)?;
    let start = bucket.updated_at;
    assert!(bucket.try_acquire(start));
    assert!(!bucket.try_acquire(start));
    assert_eq!(bucket.refill_delay(), Duration::from_nanos(1));
    assert!(bucket.try_acquire(start + Duration::from_nanos(1)));
    Ok(())
}

#[test]
fn backward_time_does_not_reset_the_refill_clock_or_duplicate_fractional_credit() -> TestResult {
    let mut bucket = limiter(1, 1)?;
    let start = bucket.updated_at;
    assert!(bucket.try_acquire(start));
    assert!(!bucket.try_acquire(start + Duration::from_millis(500)));
    assert!(!bucket.try_acquire(start));
    assert_eq!(bucket.updated_at, start + Duration::from_millis(500));
    assert_eq!(bucket.remainder, NANOS_PER_SECOND / 2);
    assert!(bucket.try_acquire(start + Duration::from_secs(1)));
    Ok(())
}
