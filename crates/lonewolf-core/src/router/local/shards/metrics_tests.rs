// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::future::Future;
use std::time::Duration;

use compio::runtime::Runtime;
use lonewolf_util::arena::{Arena, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn run(test: impl Future<Output = TestResult>) -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), test))?
}

fn account(value: &str) -> TestResult<AccountKey> {
    let mut arena = Arena::try_new(Default::default())?;
    let jid = Jid::parse_in(value, &mut arena)?;
    Ok(AccountKey::try_from(jid.resolve(&arena)?)?)
}

async fn assert_counts(
    handle: &LocalRouterHandle<GlobalChunkAllocator>,
    accounts: &[&AccountKey],
    expected: u64,
) -> TestResult {
    assert_eq!(handle.metrics().sessions(), expected);
    for account in accounts {
        let (count, actual) = handle
            .with_shard(handle.shard_index(account.as_str()), |shard| {
                (shard.session_count(), shard.counted_sessions())
            })
            .await?;
        assert_eq!(count, actual);
    }
    Ok(())
}

#[test]
fn session_gauge_follows_registration_cleanup_retirement_and_shutdown() -> TestResult {
    run(async {
        let router = LocalRouter::new(GlobalChunkAllocator);
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let bob = account("bob@localhost")?;
        let limit = NonZeroUsize::MIN.saturating_add(1);
        let desk = handle.register(&alice, Some("desk"), limit).await?;
        let phone = handle.register(&alice, Some("phone"), limit).await?;
        let bob_desk = handle.register(&bob, Some("desk"), limit).await?;
        assert_counts(&handle, &[&alice, &bob], 3).await?;
        drop(phone);
        assert_counts(&handle, &[&alice, &bob], 2).await?;
        handle.retire_account(&bob).await?;
        assert_counts(&handle, &[&alice, &bob], 1).await?;
        router.shutdown().await?;
        assert_eq!(handle.metrics().sessions(), 0);
        for account in [&alice, &bob] {
            let shard = handle.inner.slots[handle.shard_index(account.as_str())]
                .shard
                .lock()
                .await;
            assert_eq!(shard.session_count(), 0);
            assert_eq!(shard.session_count(), shard.counted_sessions());
        }
        drop((desk, bob_desk));
        Ok(())
    })
}

#[test]
fn session_gauge_is_zero_after_a_shard_panic() -> TestResult {
    run(async {
        let router = LocalRouter::new(GlobalChunkAllocator);
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let desk = handle
            .register(&alice, Some("desk"), NonZeroUsize::MIN)
            .await?;
        assert_counts(&handle, &[&alice], 1).await?;
        assert_eq!(handle.inject_panic(&alice).await, Err(RouterError::Stopped));
        assert_eq!(handle.metrics().sessions(), 0);
        let shard = handle.inner.slots[handle.shard_index(alice.as_str())]
            .shard
            .lock()
            .await;
        assert_eq!(shard.session_count(), shard.counted_sessions());
        drop(shard);
        assert!(router.shutdown().await.is_err());
        drop(desk);
        Ok(())
    })
}

#[test]
fn pending_cleanup_is_published_when_the_shard_lock_is_released() -> TestResult {
    run(async {
        let router = LocalRouter::new(GlobalChunkAllocator);
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let desk = handle
            .register(&alice, Some("desk"), NonZeroUsize::MIN)
            .await?;
        let index = handle.shard_index(alice.as_str());
        let shard = handle.inner.slots[index].shard.lock().await;
        drop(desk);
        assert_eq!(handle.metrics().sessions(), 1);
        drop(shard);
        let (count, actual) = handle
            .with_shard(index, |shard| {
                (shard.session_count(), shard.counted_sessions())
            })
            .await?;
        assert_eq!((count, actual), (0, 0));
        assert_eq!(handle.metrics().sessions(), 0);
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn session_gauge_is_zero_after_final_router_drop_with_pending_cleanup() -> TestResult {
    run(async {
        let router = LocalRouter::new(GlobalChunkAllocator);
        let handle = router.handle();
        let metrics = Arc::clone(handle.metrics());
        let alice = account("alice@localhost")?;
        let desk = handle
            .register(&alice, Some("desk"), NonZeroUsize::MIN)
            .await?;
        let index = handle.shard_index(alice.as_str());
        let shard = handle.inner.slots[index].shard.lock().await;
        drop(desk);
        assert_eq!(handle.inner.slots[index].pending.lock().len(), 1);
        assert_eq!(shard.session_count(), 1);
        assert_eq!(shard.counted_sessions(), 1);
        assert_eq!(metrics.sessions(), 1);
        drop(shard);
        drop(router);
        assert_eq!(metrics.sessions(), 1);
        drop(handle);
        assert_eq!(metrics.sessions(), 0);
        Ok(())
    })
}

#[test]
fn router_failure_clears_session_gauges_on_other_shards() -> TestResult {
    run(async {
        let mut router = LocalRouter::new(GlobalChunkAllocator);
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let mut number = 0;
        let other = loop {
            let candidate = account(&format!("user{number}@localhost"))?;
            if handle.shard_index(candidate.as_str()) != handle.shard_index(alice.as_str()) {
                break candidate;
            }
            number += 1;
        };
        let desk = handle
            .register(&alice, Some("desk"), NonZeroUsize::MIN)
            .await?;
        let other_desk = handle
            .register(&other, Some("desk"), NonZeroUsize::MIN)
            .await?;
        assert_counts(&handle, &[&alice, &other], 2).await?;
        assert_eq!(handle.inject_panic(&alice).await, Err(RouterError::Stopped));
        assert_eq!(handle.metrics().sessions(), 1);
        router.failure().await;
        assert_eq!(handle.metrics().sessions(), 0);
        drop((desk, other_desk));
        assert!(router.shutdown().await.is_err());
        Ok(())
    })
}
