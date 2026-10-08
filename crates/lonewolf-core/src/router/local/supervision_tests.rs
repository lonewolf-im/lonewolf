// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::process::Command as Process;
use std::time::Duration;

use compio::runtime::Runtime;
use lonewolf_util::arena::GlobalChunkAllocator;
use lonewolf_util::core_dispatcher::CoreDispatcher;
use lonewolf_util::pool::{PoolConfig, PooledChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::{Stanza, StanzaNamespace};
use std::pin::pin;

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const TIMEOUT: Duration = Duration::from_secs(5);

fn run(test: impl Future<Output = TestResult>) -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(TIMEOUT, test))?
}

fn account(value: &str) -> TestResult<AccountKey> {
    let mut arena = Arena::try_new(Default::default())?;
    let jid = Jid::parse_in(value, &mut arena)?;
    Ok(AccountKey::try_from(jid.resolve(&arena)?)?)
}

fn dispatcher() -> io::Result<CoreDispatcher> {
    let two = NonZeroUsize::MIN.saturating_add(1);
    match CoreDispatcher::new(two, two) {
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => {
            CoreDispatcher::new(NonZeroUsize::MIN, two)
        }
        result => result,
    }
}

#[test]
fn a_panicking_operation_fails_the_router_once_and_retires_every_shard() -> TestResult {
    run(async {
        let mut router = LocalRouter::new(GlobalChunkAllocator);
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let desk = handle
            .register(&alice, Some("desk"), NonZeroUsize::MIN)
            .await?;
        let mut number = 0;
        let other = loop {
            let candidate = account(&format!("user{number}@localhost"))?;
            if handle.shard_index(candidate.as_str()) != handle.shard_index(alice.as_str()) {
                break candidate;
            }
            number += 1;
        };
        let other_desk = handle
            .register(&other, Some("desk"), NonZeroUsize::MIN)
            .await?;
        assert!(router.failure().now_or_never().is_none());
        assert_eq!(handle.inject_panic(&alice).await, Err(RouterError::Stopped));
        let failure = router.failure().await;
        assert_eq!(failure.shard_id, handle.shard_index(alice.as_str()));
        assert_eq!(handle.inject_panic(&other).await, Err(RouterError::Stopped));
        assert_eq!(router.state(), RouterState::Failed(failure));
        assert_eq!(handle.state(), RouterState::Failed(failure));
        assert_eq!(router.failure().await, failure);
        for registration in [&desk, &other_desk] {
            assert!(!registration.liveness().is_alive());
            assert_eq!(
                registration.wait_retired().await?.cause,
                RetireCause::RouterStopped
            );
            assert!(registration.recv().await.is_none());
        }
        assert!(matches!(
            handle
                .register(&alice, Some("phone"), NonZeroUsize::MIN)
                .await,
            Err(RouterError::Stopped)
        ));
        assert_eq!(
            handle.resource_match(&alice, "desk").await,
            Err(RouterError::Stopped)
        );
        router.stop();
        assert_eq!(router.state(), RouterState::Failed(failure));
        assert!(router.shutdown().await.is_err());
        Ok(())
    })
}

#[test]
fn normal_stop_is_not_a_failure() -> TestResult {
    run(async {
        let mut router = LocalRouter::new(GlobalChunkAllocator);
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let registered = handle
            .register(&alice, Some("desk"), NonZeroUsize::MIN)
            .await?;
        router.stop();
        assert_eq!(handle.state(), RouterState::Stopping);
        assert!(matches!(
            handle
                .register(&alice, Some("phone"), NonZeroUsize::MIN)
                .await,
            Err(RouterError::Stopped)
        ));
        assert_eq!(
            handle
                .resource_match(&alice, "desk")
                .await?
                .map(|resource| resource.token),
            Some(registered.token)
        );
        assert!(router.failure().now_or_never().is_none());
        router.shutdown().await?;
        assert_eq!(
            registered.wait_retired().await?.cause,
            RetireCause::RouterStopped
        );
        assert_eq!(
            handle.resource_match(&alice, "desk").await,
            Err(RouterError::Stopped)
        );
        Ok(())
    })
}

#[test]
fn a_panic_while_stopping_makes_shutdown_fail_without_changing_state() -> TestResult {
    run(async {
        let router = LocalRouter::new(GlobalChunkAllocator);
        let handle = router.handle();
        router.stop();
        assert_eq!(
            handle.inject_panic(&account("alice@localhost")?).await,
            Err(RouterError::Stopped)
        );
        assert_eq!(router.state(), RouterState::Stopping);
        assert!(router.shutdown().await.is_err());
        Ok(())
    })
}

#[test]
fn active_tagged_callback_panic_cleans_up_without_aborting() -> TestResult {
    let output = Process::new(std::env::current_exe()?)
        .args([
            "router::local::supervision_tests::tagged_callback_panic_process",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .env("LONEWOLF_ROUTER_PANIC_TEST", "1")
        .output()?;
    assert!(
        output.status.success(),
        "status={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
#[ignore = "subprocess entry point for the router panic fixture"]
fn tagged_callback_panic_process() -> TestResult {
    if std::env::var_os("LONEWOLF_ROUTER_PANIC_TEST").is_none() {
        return Ok(());
    }
    run(async {
        let dispatcher = dispatcher()?;
        let pool = Arc::new(PooledChunkAllocator::try_new(PoolConfig {
            total_bytes: NonZeroUsize::new(8 * 1024 * 1024).ok_or("zero pool")?,
            shards_per_bucket: NonZeroUsize::MIN,
        })?);
        let mut router = LocalRouter::new(Arc::clone(&pool));
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let registration = handle
            .register(&alice, Some("desk"), NonZeroUsize::MIN)
            .await?;
        registration.tag(SessionTag::Interested).await?;
        let old = registration.handle();
        let mut recipient_arena = Arena::try_new(Default::default())?;
        let recipient = Jid::parse_in("bob@localhost/phone", &mut recipient_arena)?;
        old.record_directed_presence(
            DirectedRecipient::new(recipient.resolve(&recipient_arena)?),
            true,
        )
        .await?;
        let mut arena = Arena::try_new_in(Default::default(), Arc::clone(&pool))?;
        let target = Jid::parse_in("alice@localhost/desk", &mut arena)?;
        let stanza = Stanza::builder_in(
            StanzaType::Presence(PresenceType::Available),
            StanzaNamespace::Client,
            &mut arena,
        )
        .to(Some(target))?
        .build()?;
        let cached = RoutedStanza::from_parts(stanza, arena);
        old.set_presence(Some(0), cached.clone(), Some(cached))
            .await?;
        assert!(
            handle
                .has_directed_grant(&alice, "desk", recipient.resolve(&recipient_arena)?)
                .await?
        );
        let mut arena = Arena::try_new_in(Default::default(), Arc::clone(&pool))?;
        let target = Jid::parse_in("alice@localhost/desk", &mut arena)?;
        let stanza = Stanza::builder_in(
            StanzaType::Message(MessageType::Chat),
            StanzaNamespace::Client,
            &mut arena,
        )
        .to(Some(target))?
        .build()?;
        handle
            .deliver_full(RoutedStanza::from_parts(stanza, arena))
            .await?;
        let (entered, entering) = oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let (capture, captured) = oneshot::channel::<()>();
        let mut captured = pin!(captured);
        assert!(captured.as_mut().now_or_never().is_none());
        let mut entered = Some(entered);
        let mut capture = Some(capture);
        let caller_handle = handle.clone();
        let caller_account = alice.clone();
        let caller = dispatcher
            .handle()
            .dispatch_at(0, move |_| async move {
                caller_handle
                    .deliver_to_tagged(&caller_account, SessionTag::Interested, move |_: &str| {
                        let _keep_capture = &mut capture;
                        if let Some(entered) = entered.take() {
                            let _ = entered.send(());
                        }
                        assert!(released.recv().is_ok());
                        panic!("seeded-sensitive-router-payload");
                    })
                    .await
            })
            .await?;
        entering.await?;
        let mut arena = Arena::try_new_in(Default::default(), Arc::clone(&pool))?;
        let target = Jid::parse_in("alice@localhost/desk", &mut arena)?;
        let stanza = Stanza::builder_in(
            StanzaType::Message(MessageType::Chat),
            StanzaNamespace::Client,
            &mut arena,
        )
        .to(Some(target))?
        .build()?;
        let mut contender = pin!(handle.deliver_full(RoutedStanza::from_parts(stanza, arena)));
        assert!(futures_util::poll!(contender.as_mut()).is_pending());
        assert!(
            pool.stats()
                .buckets
                .iter()
                .any(|bucket| bucket.available_chunks < bucket.total_chunks)
        );
        release.send(())?;
        assert_eq!(caller.await?, Err(RouterError::Stopped));
        assert_eq!(contender.await, Err(RouterError::Stopped));
        assert!(captured.await.is_err());
        let failure = router.failure().await;
        assert_eq!(failure.shard_id, handle.shard_index(alice.as_str()));
        assert!(!old.liveness.is_alive());
        assert_eq!(
            handle
                .has_directed_grant(&alice, "desk", recipient.resolve(&recipient_arena)?)
                .await,
            Err(RouterError::Stopped)
        );
        assert!(registration.recv().await.is_none());
        assert_eq!(
            registration.wait_retired().await?.cause,
            RetireCause::RouterStopped
        );
        assert!(
            pool.stats()
                .buckets
                .iter()
                .all(|bucket| bucket.available_chunks == bucket.total_chunks)
        );
        assert!(router.shutdown().await.is_err());

        let replacement = LocalRouter::new(Arc::clone(&pool));
        let new = replacement
            .handle()
            .register(&alice, Some("desk"), NonZeroUsize::MIN)
            .await?;
        assert_eq!(old.token, new.token);
        drop(registration);
        assert_eq!(
            old.finish_presence(old.token).await,
            Err(RouterError::Stopped)
        );
        assert!(new.liveness().is_alive());
        assert_eq!(
            replacement
                .handle()
                .resource_match(&alice, "desk")
                .await?
                .map(|resource| resource.token),
            Some(new.token)
        );
        assert!(new.take_queued().is_empty());
        drop(new);
        drop(old);
        replacement.shutdown().await?;
        dispatcher.shutdown(TIMEOUT).await?;
        Ok(())
    })
}
