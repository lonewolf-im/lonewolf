// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::num::NonZeroUsize;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use compio::runtime::Runtime;

use super::*;

#[test]
fn capacity_is_released_with_the_permit() -> Result<(), Box<dyn Error>> {
    let limiter = Arc::new(UnauthenticatedLimiter::new(NonZeroUsize::MIN));
    Runtime::new()?.block_on(async {
        let now = Instant::now();
        let Admission::Allowed(permit) = limiter.reserve(now).await else {
            return Err("first connection was denied".into());
        };
        assert!(matches!(
            limiter.reserve(now).await,
            Admission::Denied {
                report_count: Some(1)
            }
        ));
        drop(permit);
        assert!(matches!(limiter.reserve(now).await, Admission::Allowed(_)));
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn concurrent_workers_share_the_exact_capacity() -> Result<(), Box<dyn Error>> {
    let limiter = Arc::new(UnauthenticatedLimiter::new(
        NonZeroUsize::new(64).ok_or("invalid capacity")?,
    ));
    let ready = Arc::new(Barrier::new(9));
    let mut tasks = Vec::with_capacity(8);
    for _ in 0..8 {
        let limiter = Arc::clone(&limiter);
        let ready = Arc::clone(&ready);
        tasks.push(std::thread::spawn(
            move || -> std::io::Result<Vec<UnauthenticatedPermit>> {
                let runtime = Runtime::new()?;
                ready.wait();
                Ok(runtime.block_on(async {
                    let mut held = Vec::new();
                    for _ in 0..32 {
                        if let Admission::Allowed(permit) = limiter.reserve(Instant::now()).await {
                            held.push(permit);
                        }
                    }
                    held
                }))
            },
        ));
    }
    ready.wait();
    let mut held = Vec::new();
    for task in tasks {
        held.extend(task.join().map_err(|_| "admission worker panicked")??);
    }
    assert_eq!(held.len(), 64);
    assert_eq!(limiter.active.load(Ordering::Acquire), 64);
    drop(held);
    assert_eq!(limiter.active.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn rejection_reports_are_aggregated() -> Result<(), Box<dyn Error>> {
    let limiter = Arc::new(UnauthenticatedLimiter::new(NonZeroUsize::MIN));
    Runtime::new()?.block_on(async {
        let now = Instant::now();
        let Admission::Allowed(_permit) = limiter.reserve(now).await else {
            return Err("first connection was denied".into());
        };
        assert!(matches!(
            limiter.reserve(now).await,
            Admission::Denied {
                report_count: Some(1)
            }
        ));
        assert!(matches!(
            limiter.reserve(now).await,
            Admission::Denied { report_count: None }
        ));
        assert!(matches!(
            limiter.reserve(now + Duration::from_secs(1)).await,
            Admission::Denied {
                report_count: Some(2)
            }
        ));
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn largest_capacity_rejects_without_overflow() -> Result<(), Box<dyn Error>> {
    let limiter = Arc::new(UnauthenticatedLimiter::new(
        NonZeroUsize::new(usize::MAX).ok_or("invalid capacity")?,
    ));
    limiter.active.store(usize::MAX, Ordering::Release);
    Runtime::new()?.block_on(async {
        assert!(matches!(
            limiter.reserve(Instant::now()).await,
            Admission::Denied { .. }
        ));
    });
    Ok(())
}
