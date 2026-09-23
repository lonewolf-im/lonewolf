// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use compio::runtime::Runtime;

use super::*;

#[test]
fn capacity_is_held_until_the_permit_drops() -> Result<(), Box<dyn Error>> {
    let limiter = ConnectionLimiter::new(1);
    let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
    Runtime::new()?.block_on(async {
        let now = Instant::now();
        let first = match limiter.reserve(source, now).await {
            ConnectionAdmission::Allowed(permit) => permit,
            ConnectionAdmission::Denied { .. } => panic!("first connection was denied"),
        };
        assert!(matches!(
            limiter.reserve(source, now).await,
            ConnectionAdmission::Denied {
                outcome: "connection_limit",
                ..
            }
        ));
        assert!(matches!(
            limiter
                .reserve(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), now)
                .await,
            ConnectionAdmission::Allowed(_)
        ));
        drop(first);
        assert!(matches!(
            limiter.reserve(source, now).await,
            ConnectionAdmission::Allowed(_)
        ));
    });
    Ok(())
}

#[test]
fn active_sources_survive_cleanup_when_tracking_is_full() -> Result<(), Box<dyn Error>> {
    let limiter = ConnectionLimiter::new(1);
    Runtime::new()?.block_on(async {
        let now = Instant::now();
        let first = IpAddr::V4(Ipv4Addr::new(192, 0, 0, 0));
        let first_permit = match limiter.reserve(first, now).await {
            ConnectionAdmission::Allowed(permit) => permit,
            ConnectionAdmission::Denied { .. } => panic!("first connection was denied"),
        };
        let mut held = Vec::with_capacity(MAX_TRACKED_SOURCES);
        held.push(first_permit);
        for index in 1..MAX_TRACKED_SOURCES {
            let source = IpAddr::V4(Ipv4Addr::new(192, 0, (index / 256) as u8, index as u8));
            match limiter.reserve(source, now).await {
                ConnectionAdmission::Allowed(permit) => held.push(permit),
                ConnectionAdmission::Denied { .. } => panic!("tracked source was denied"),
            }
        }
        let newcomer = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        assert!(matches!(
            limiter.reserve(newcomer, now).await,
            ConnectionAdmission::Denied {
                outcome: "source_tracking_full",
                ..
            }
        ));
        held.truncate(1);
        assert!(matches!(
            limiter
                .reserve(newcomer, now + Duration::from_secs(2))
                .await,
            ConnectionAdmission::Allowed(_)
        ));
        assert!(matches!(
            limiter.reserve(first, now + Duration::from_secs(2)).await,
            ConnectionAdmission::Denied {
                outcome: "connection_limit",
                ..
            }
        ));
        held.clear();
        assert!(matches!(
            limiter.reserve(first, now + Duration::from_secs(2)).await,
            ConnectionAdmission::Allowed(_)
        ));
    });
    Ok(())
}

#[test]
fn concurrent_workers_share_one_connection_allowance() -> Result<(), Box<dyn Error>> {
    let limiter = Arc::new(ConnectionLimiter::new(64));
    let ready = Arc::new(Barrier::new(9));
    let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let now = Instant::now();
    let mut tasks = Vec::with_capacity(8);
    for _ in 0..8 {
        let limiter = Arc::clone(&limiter);
        let ready = Arc::clone(&ready);
        tasks.push(std::thread::spawn(
            move || -> std::io::Result<Vec<ConnectionPermit>> {
                let runtime = Runtime::new()?;
                ready.wait();
                Ok(runtime.block_on(async {
                    let mut held = Vec::new();
                    for _ in 0..32 {
                        if let ConnectionAdmission::Allowed(permit) =
                            limiter.reserve(source, now).await
                        {
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
        held.extend(task.join().map_err(|_| "connection worker panicked")??);
    }
    assert_eq!(held.len(), 64);
    assert!(matches!(
        Runtime::new()?.block_on(limiter.reserve(source, now)),
        ConnectionAdmission::Denied {
            outcome: "connection_limit",
            ..
        }
    ));
    held.clear();
    assert!(matches!(
        Runtime::new()?.block_on(limiter.reserve(source, now)),
        ConnectionAdmission::Allowed(_)
    ));
    Ok(())
}

#[test]
fn connection_rejections_are_aggregated_per_interval() -> Result<(), Box<dyn Error>> {
    let limiter = ConnectionLimiter::new(1);
    let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
    Runtime::new()?.block_on(async {
        let now = Instant::now();
        let held = match limiter.reserve(source, now).await {
            ConnectionAdmission::Allowed(permit) => permit,
            ConnectionAdmission::Denied { .. } => panic!("first connection was denied"),
        };
        assert!(matches!(
            limiter.reserve(source, now).await,
            ConnectionAdmission::Denied {
                report_count: Some(1),
                ..
            }
        ));
        for millis in [100, 200] {
            assert!(matches!(
                limiter
                    .reserve(source, now + Duration::from_millis(millis))
                    .await,
                ConnectionAdmission::Denied {
                    report_count: None,
                    ..
                }
            ));
        }
        assert!(matches!(
            limiter.reserve(source, now + Duration::from_secs(1)).await,
            ConnectionAdmission::Denied {
                report_count: Some(3),
                ..
            }
        ));
        drop(held);
    });
    Ok(())
}
