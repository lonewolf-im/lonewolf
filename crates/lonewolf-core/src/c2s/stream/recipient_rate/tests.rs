// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn count(value: usize) -> Result<NonZeroUsize, &'static str> {
    NonZeroUsize::new(value).ok_or("zero count")
}

#[test]
fn repeats_are_free_and_denials_do_not_enter_the_cache() -> TestResult {
    let now = Instant::now();
    let mut limiter = RecipientLimiter::new(NonZeroUsize::MIN, count(3)?, now);
    for recipient in ["alice@example.org", "bob@example.org", "carol@example.org"] {
        assert!(limiter.admit(recipient, now));
        assert!(limiter.admit(recipient, now));
    }
    for _ in 0..3 {
        assert!(!limiter.admit("dave@example.org", now));
    }
    for recipient in ["alice@example.org", "bob@example.org", "carol@example.org"] {
        assert!(limiter.admit(recipient, now));
    }
    assert_eq!(limiter.len, 3);
    Ok(())
}

#[test]
fn refill_admits_at_the_exact_fractional_boundary() -> TestResult {
    let now = Instant::now();
    let mut limiter = RecipientLimiter::new(count(3)?, count(2)?, now);
    assert!(limiter.admit("alice@example.org", now));
    assert!(limiter.admit("dave@example.org", now));
    assert!(!limiter.admit("bob@example.org", now + Duration::from_millis(100)));
    assert!(!limiter.admit("bob@example.org", now + Duration::from_nanos(333_333_333)));
    assert!(limiter.admit("bob@example.org", now + Duration::from_nanos(333_333_334)));
    assert!(!limiter.admit("carol@example.org", now + Duration::from_nanos(666_666_666)));
    assert!(limiter.admit("carol@example.org", now + Duration::from_nanos(666_666_667)));
    Ok(())
}

#[test]
fn the_sixty_fifth_admission_evicts_the_oldest_and_charges_it_again() -> TestResult {
    let now = Instant::now();
    let mut limiter = RecipientLimiter::new(NonZeroUsize::MIN, count(66)?, now);
    for index in 0..64 {
        assert!(limiter.admit(&format!("user{index}@example.org"), now));
    }
    assert_eq!(limiter.bucket.available(), 2);
    assert!(limiter.admit("user0@example.org", now));
    assert_eq!(limiter.bucket.available(), 2);
    assert!(limiter.admit("user64@example.org", now));
    assert!(limiter.admit("user0@example.org", now));
    assert_eq!(limiter.bucket.available(), 0);
    assert!(!limiter.admit("user1@example.org", now));
    Ok(())
}

#[test]
fn denials_do_not_evict_a_full_cache() -> TestResult {
    let now = Instant::now();
    let mut limiter = RecipientLimiter::new(NonZeroUsize::MIN, count(64)?, now);
    for index in 0..64 {
        assert!(limiter.admit(&format!("user{index}@example.org"), now));
    }
    let recent = limiter.recent;
    for index in 64..128 {
        assert!(!limiter.admit(&format!("user{index}@example.org"), now));
    }
    assert_eq!(limiter.recent, recent);
    assert_eq!(limiter.next, 0);
    for index in 0..64 {
        assert!(limiter.admit(&format!("user{index}@example.org"), now));
    }
    Ok(())
}
