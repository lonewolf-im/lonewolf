// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::process::Command as ProcessCommand;
use std::time::Duration;

use compio::runtime::Runtime;
use futures_util::future::join;
use lonewolf_util::arena::GlobalChunkAllocator;
use lonewolf_util::core_dispatcher::CoreDispatcher;
use lonewolf_util::pool::{PoolConfig, PooledChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::{Stanza, StanzaNamespace};

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
fn unexpected_completion_survives_observer_cancellation_and_closes_every_shard() -> TestResult {
    run(async {
        let dispatcher = dispatcher()?;
        let mut router = LocalRouter::start(&dispatcher.handle(), GlobalChunkAllocator).await?;
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let registered = handle
            .register(&alice, Some("desk"), NonZeroUsize::MIN)
            .await?;
        assert!(router.failure().now_or_never().is_none());
        let shard = handle.shard(alice.as_str());
        let (entered, entering) = oneshot::channel();
        let (release, released) = oneshot::channel();
        shard
            .send(Command::Suspend {
                entered,
                release: released,
            })
            .await?;
        entering.await?;
        let mut replies = Vec::with_capacity(SHARD_QUEUE_CAPACITY);
        for _ in 0..SHARD_QUEUE_CAPACITY {
            let (reply, receiver) = oneshot::channel();
            shard.try_send(Command::ResourceMatch {
                account: alice.clone(),
                resource: "desk".into(),
                reply,
            })?;
            replies.push(receiver);
        }
        let (reply, result) = oneshot::channel();
        let mut admission = pin!(shard.send(Command::ResourceMatch {
            account: alice.clone(),
            resource: "desk".into(),
            reply
        }));
        assert!(admission.as_mut().now_or_never().is_none());
        shard.close();
        assert!(admission.await.is_err());
        assert!(result.await.is_err());
        assert!(router.failure().now_or_never().is_none());
        release.send(()).map_err(|_| "actor gate closed")?;
        let failure = router.failure().await;
        assert_eq!(failure.reason, RouterFailureReason::Completed);
        for reply in replies {
            assert!(reply.await.is_err());
        }
        assert_eq!(router.state(), RouterState::Failed(failure));
        assert_eq!(handle.state(), RouterState::Failed(failure));
        assert_eq!(router.failure().await, failure);
        assert!(!registered.liveness().is_alive());
        assert_eq!(
            registered.wait_retired().await?.cause,
            RetireCause::RouterStopped
        );
        assert!(handle.shards.iter().all(Sender::is_closed));
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
        dispatcher.shutdown(TIMEOUT).await?;
        Ok(())
    })
}

#[test]
fn competing_completions_keep_first_failure_and_normal_stop_is_not_a_failure() -> TestResult {
    run(async {
        let dispatcher = dispatcher()?;
        let mut router = LocalRouter::start(&dispatcher.handle(), GlobalChunkAllocator).await?;
        for shard in router.handle.shards.iter() {
            shard.close();
        }
        let first = router.failure().await;
        assert_eq!(first.reason, RouterFailureReason::Completed);
        assert_eq!(router.failure().await, first);
        assert!(router.shutdown().await.is_err());

        let mut router = LocalRouter::start(&dispatcher.handle(), GlobalChunkAllocator).await?;
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
        dispatcher.shutdown(TIMEOUT).await?;
        Ok(())
    })
}

#[test]
fn cancellation_revokes_ownership_before_reporting_and_wakes_pending_admission() -> TestResult {
    run(async {
        let dispatcher = dispatcher()?;
        let mut router = LocalRouter::start(&dispatcher.handle(), GlobalChunkAllocator).await?;
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let registered = handle
            .register(&alice, Some("desk"), NonZeroUsize::MIN)
            .await?;
        let shard = handle.shard(alice.as_str());
        let (entered, entering) = oneshot::channel();
        let (_release, released) = oneshot::channel();
        shard
            .send(Command::Suspend {
                entered,
                release: released,
            })
            .await?;
        entering.await?;
        let mut replies = Vec::with_capacity(SHARD_QUEUE_CAPACITY);
        for _ in 0..SHARD_QUEUE_CAPACITY {
            let (reply, receiver) = oneshot::channel();
            shard.try_send(Command::ResourceMatch {
                account: alice.clone(),
                resource: "desk".into(),
                reply,
            })?;
            replies.push(receiver);
        }
        let (reply, result) = oneshot::channel();
        let mut admission = pin!(shard.send(Command::ResourceMatch {
            account: alice.clone(),
            resource: "desk".into(),
            reply
        }));
        assert!(admission.as_mut().now_or_never().is_none());
        let (stopped, failure) =
            join(dispatcher.shutdown_at(Instant::now()), router.failure()).await;
        assert_eq!(
            stopped.err().map(|error| error.kind()),
            Some(io::ErrorKind::TimedOut)
        );
        assert_eq!(failure.reason, RouterFailureReason::Cancelled);
        assert!(!registered.liveness().is_alive());
        assert_eq!(
            registered.wait_retired().await?.cause,
            RetireCause::RouterStopped
        );
        assert!(admission.await.is_err());
        assert!(result.await.is_err());
        for reply in replies {
            assert!(reply.await.is_err());
        }
        assert!(router.shutdown().await.is_err());
        Ok(())
    })
}

#[test]
fn active_tagged_callback_panic_cleans_up_without_aborting() -> TestResult {
    let output = ProcessCommand::new(std::env::current_exe()?)
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
        let mut router = LocalRouter::start(&dispatcher.handle(), Arc::clone(&pool)).await?;
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
        let mut caller = pin!(handle.deliver_to_tagged(
            &alice,
            SessionTag::Interested,
            Box::new(move |_: &str| {
                let _keep_capture = &mut capture;
                if let Some(entered) = entered.take() {
                    let _ = entered.send(());
                }
                assert!(released.recv().is_ok());
                panic!("seeded-sensitive-router-payload");
            })
        ));
        assert!(caller.as_mut().now_or_never().is_none());
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
        let queued = RoutedStanza::from_parts(stanza, arena);
        let (reply, replying) = oneshot::channel();
        handle.shard(alice.as_str()).try_send(Command::Deliver {
            stanza: queued,
            fallback_chat: false,
            source: None,
            reply,
        })?;
        assert!(
            pool.stats()
                .buckets
                .iter()
                .any(|bucket| bucket.available_chunks < bucket.total_chunks)
        );
        release.send(())?;
        assert_eq!(caller.await, Err(RouterError::Stopped));
        assert!(captured.await.is_err());
        let failure = router.failure().await;
        assert_eq!(failure.reason, RouterFailureReason::Panicked);
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
        assert!(replying.await.is_err());
        assert!(
            pool.stats()
                .buckets
                .iter()
                .all(|bucket| bucket.available_chunks == bucket.total_chunks)
        );
        assert!(router.shutdown().await.is_err());

        let replacement = LocalRouter::start(&dispatcher.handle(), Arc::clone(&pool)).await?;
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
        assert!(dispatcher.shutdown(TIMEOUT).await.is_err());
        Ok(())
    })
}
