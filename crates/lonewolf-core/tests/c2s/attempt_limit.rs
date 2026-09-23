// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroUsize;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use crate::config::limits::EventRate;
use compio::runtime::Runtime;

use super::*;

#[test]
fn concurrent_workers_use_the_full_shared_burst() -> Result<(), Box<dyn Error>> {
    let rate = EventRate {
        per_second: NonZeroUsize::MIN,
        burst: NonZeroUsize::new(8_192).ok_or("invalid burst")?,
    };
    let limiter = Arc::new(AttemptLimiter::new(&rate));
    let ready = Arc::new(Barrier::new(9));
    let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let now = Instant::now();
    let mut tasks = Vec::with_capacity(8);
    for _ in 0..8 {
        let limiter = Arc::clone(&limiter);
        let ready = Arc::clone(&ready);
        tasks.push(std::thread::spawn(move || -> std::io::Result<usize> {
            let runtime = Runtime::new()?;
            ready.wait();
            Ok(runtime.block_on(async {
                let mut allowed = 0;
                for _ in 0..1_024 {
                    allowed += usize::from(limiter.admit(source, now).await.is_allowed());
                }
                allowed
            }))
        }));
    }
    ready.wait();
    let mut allowed = 0;
    for task in tasks {
        allowed += task.join().map_err(|_| "admission worker panicked")??;
    }
    assert_eq!(allowed, 8_192);
    assert!(
        !Runtime::new()?
            .block_on(limiter.admit(source, now))
            .is_allowed()
    );
    Ok(())
}

#[test]
fn new_sources_are_denied_at_capacity_until_existing_buckets_refill() -> Result<(), Box<dyn Error>>
{
    let rate = EventRate {
        per_second: NonZeroUsize::MIN,
        burst: NonZeroUsize::MIN,
    };
    let limiter = AttemptLimiter::new(&rate);
    let runtime = Runtime::new()?;
    runtime.block_on(async {
        let now = Instant::now();
        let first = IpAddr::V4(Ipv4Addr::new(192, 0, 0, 0));
        for index in 0..MAX_TRACKED_SOURCES {
            let source = IpAddr::V4(Ipv4Addr::new(192, 0, (index / 256) as u8, index as u8));
            assert!(limiter.admit(source, now).await.is_allowed());
        }
        let newcomer = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        assert!(!limiter.admit(first, now).await.is_allowed());
        assert!(matches!(
            limiter.admit(newcomer, now).await,
            Admission::Denied {
                outcome: "source_tracking_full",
                ..
            }
        ));
        assert_eq!(
            limiter.state.lock().await.sources.len(),
            MAX_TRACKED_SOURCES
        );
        assert!(!limiter.admit(first, now).await.is_allowed());
        assert!(
            limiter
                .admit(newcomer, now + std::time::Duration::from_secs(2))
                .await
                .is_allowed()
        );
    });
    Ok(())
}

#[test]
fn sources_have_independent_bursts_and_fractional_refills() -> Result<(), Box<dyn Error>> {
    let rate = EventRate {
        per_second: NonZeroUsize::new(2).ok_or("invalid rate")?,
        burst: NonZeroUsize::new(2).ok_or("invalid burst")?,
    };
    let limiter = AttemptLimiter::new(&rate);
    let first = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let second = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    Runtime::new()?.block_on(async {
        let now = Instant::now();
        assert!(limiter.admit(first, now).await.is_allowed());
        assert!(limiter.admit(first, now).await.is_allowed());
        assert!(!limiter.admit(first, now).await.is_allowed());
        assert!(limiter.admit(second, now).await.is_allowed());
        assert!(
            !limiter
                .admit(first, now + Duration::from_millis(250))
                .await
                .is_allowed()
        );
        assert!(
            limiter
                .admit(first, now + Duration::from_millis(500))
                .await
                .is_allowed()
        );
        assert!(
            !limiter
                .admit(first, now + Duration::from_millis(500))
                .await
                .is_allowed()
        );
        assert!(
            limiter
                .admit(first, now + Duration::from_secs(1))
                .await
                .is_allowed()
        );
    });
    Ok(())
}

#[test]
fn rejections_report_at_most_once_per_interval_with_a_count() -> Result<(), Box<dyn Error>> {
    let rate = EventRate {
        per_second: NonZeroUsize::MIN,
        burst: NonZeroUsize::MIN,
    };
    let limiter = AttemptLimiter::new(&rate);
    let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
    Runtime::new()?.block_on(async {
        let now = Instant::now();
        assert!(limiter.admit(source, now).await.is_allowed());
        assert!(matches!(
            limiter.admit(source, now).await,
            Admission::Denied {
                report_count: Some(1),
                ..
            }
        ));
        for millis in [100, 200] {
            assert!(matches!(
                limiter
                    .admit(source, now + Duration::from_millis(millis))
                    .await,
                Admission::Denied {
                    report_count: None,
                    ..
                }
            ));
        }
        let next = now + Duration::from_secs(1);
        assert!(limiter.admit(source, next).await.is_allowed());
        assert!(matches!(
            limiter.admit(source, next).await,
            Admission::Denied {
                report_count: Some(3),
                ..
            }
        ));
    });
    Ok(())
}
