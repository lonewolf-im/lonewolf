// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::time::Duration;

use compio::runtime::Runtime;
use compio::time::timeout;

use super::*;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn acquisition_charges_the_configured_burst_and_refill_rate() -> TestResult {
    let per_second = NonZeroUsize::new(2).ok_or("invalid rate")?;
    let burst = NonZeroUsize::new(2).ok_or("invalid burst")?;
    let start = Instant::now();
    let mut limiter = StanzaLimiter {
        per_second,
        burst,
        bucket: TokenBucket::new(burst, start),
    };
    assert!(limiter.try_acquire(start));
    assert!(limiter.try_acquire(start));
    assert!(!limiter.try_acquire(start));
    assert!(!limiter.try_acquire(start + Duration::from_millis(250)));
    assert!(limiter.try_acquire(start + Duration::from_millis(500)));
    assert!(!limiter.try_acquire(start + Duration::from_millis(500)));
    assert!(limiter.try_acquire(start + Duration::from_secs(1)));
    Ok(())
}

#[test]
fn acquisition_waits_for_refill_after_the_burst_and_survives_cancellation() -> TestResult {
    Runtime::new()?.block_on(async {
        let mut limiter = StanzaLimiter::new(
            NonZeroUsize::new(20).ok_or("invalid rate")?,
            NonZeroUsize::new(2).ok_or("invalid burst")?,
        );
        limiter.acquire().await;
        limiter.acquire().await;
        assert!(
            timeout(Duration::from_millis(10), limiter.acquire())
                .await
                .is_err()
        );
        timeout(Duration::from_millis(200), limiter.acquire()).await?;
        timeout(Duration::from_millis(200), limiter.acquire()).await?;
        Ok(())
    })
}
