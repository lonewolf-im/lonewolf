// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::future::{Future, pending};
use std::num::{NonZeroU64, NonZeroUsize};
use std::pin::pin;

use compio::runtime::Runtime;
use futures_util::poll;
use lonewolf_util::arena::{ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::parser::{ParserConfig, StreamEvent, XmppParser};
use prometheus_client::registry::Registry;

use super::*;
use crate::config::Config;
use crate::router::{Router, RouterError, local::LocalRouter};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
type Manager = RemoteRouter<GlobalChunkAllocator>;
const TIMEOUT: Duration = Duration::from_secs(5);

pub(super) fn run(test: impl Future<Output = TestResult>) -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(TIMEOUT, test))?
}

pub(super) fn manager(limits: S2sLimits) -> TestResult<Manager> {
    manager_with_allocator(limits, GlobalChunkAllocator)
}

pub(super) fn manager_with_allocator<A: ChunkAllocator + Clone>(
    limits: S2sLimits,
    allocator: A,
) -> TestResult<RemoteRouter<A>> {
    let config = Config::default();
    let hosts = Hosts::new(&config.hosts, config.xmpp.default_host.as_deref())?;
    let trust = PeerTrust::load(&config.s2s.tls, hosts.crypto_provider())?;
    Ok(RemoteRouter::new(
        hosts,
        trust,
        Arc::new(Resolver::new(&config.s2s)?),
        &limits,
        allocator,
        S2sMetrics::new(0),
    ))
}

pub(super) async fn stanza(xml: &str) -> TestResult<RoutedStanza<GlobalChunkAllocator>> {
    stanza_in(xml, GlobalChunkAllocator).await
}

pub(super) async fn stanza_in<A: ChunkAllocator + Clone>(
    xml: &str,
    allocator: A,
) -> TestResult<RoutedStanza<A>> {
    let xml = format!(
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' version='1.0'>{xml}"
    );
    let mut parser = XmppParser::new(
        xml.as_bytes(),
        ParserConfig {
            max_stanza_bytes: NonZeroUsize::new(65536).ok_or("invalid size")?,
            arena: ArenaConfig::default(),
        },
        allocator,
    );
    assert!(matches!(
        parser.next_event().await?,
        Some(StreamEvent::StreamStart { .. })
    ));
    match parser.next_event().await? {
        Some(StreamEvent::Stanza(parsed)) => Ok(RoutedStanza::from_parsed(parsed)),
        _ => Err("expected stanza".into()),
    }
}

pub(super) async fn message() -> TestResult<RoutedStanza<GlobalChunkAllocator>> {
    stanza("<message from='alice@localhost/desk' to='bob@remote.test/phone'><body>payload</body></message>").await
}

fn failure(
    started_at: Instant,
    delay: Duration,
    failures: u32,
    condition: RemoteFailure,
) -> Entry<GlobalChunkAllocator> {
    Entry::Backoff {
        started_at,
        delay,
        condition,
        failures,
    }
}

fn pair(remote: &str) -> Pair {
    ("localhost".into(), remote.into())
}

pub(super) fn render(metrics: &Arc<S2sMetrics>) -> TestResult<String> {
    let mut registry = Registry::default();
    metrics.register(&mut registry);
    let mut output = String::new();
    prometheus_client::encoding::text::encode(&mut output, &registry)?;
    Ok(output)
}

#[test]
fn count_and_byte_refusals_release_only_their_own_reservations() -> TestResult {
    run(async {
        let mut limits = S2sLimits {
            max_queued_stanzas_per_link: NonZeroUsize::MIN,
            ..Default::default()
        };
        let manager = manager(limits.clone())?;
        let message = message().await?;
        let bytes = stanza_bytes(&message).ok_or("size")?;
        let task = manager
            .admit("localhost", "remote.test", message.clone())
            .map_err(|error| format!("{error:?}"))?
            .ok_or("launch")?;
        assert!(matches!(
            manager.admit("localhost", "remote.test", message.clone()),
            Err(RemoteError::Busy)
        ));
        assert_eq!(task.counters.count.load(Ordering::Relaxed), 1);
        assert_eq!(task.counters.bytes.load(Ordering::Relaxed), bytes);
        drop(task.receiver.recv().await?.into_stanza());
        assert_eq!(task.counters.count.load(Ordering::Relaxed), 0);
        assert_eq!(task.counters.bytes.load(Ordering::Relaxed), 0);
        assert!(
            manager
                .admit("localhost", "remote.test", message.clone())
                .map_err(|error| format!("{error:?}"))?
                .is_none()
        );
        assert!(
            render(&manager.inner.metrics)?
                .contains("s2s_admission_rejections_total{reason=\"queue_full\"} 1")
        );
        drop(task.receiver);
        assert_eq!(task.counters.bytes.load(Ordering::Relaxed), 0);
        assert!(matches!(
            manager.admit("localhost", "remote.test", message.clone()),
            Err(RemoteError::Busy)
        ));
        assert_eq!(task.counters.count.load(Ordering::Relaxed), 0);
        assert_eq!(task.counters.bytes.load(Ordering::Relaxed), 0);
        drop(task.guard);
        manager.join(Instant::now() + TIMEOUT).await?;
        limits.max_queued_stanzas_per_link = NonZeroUsize::new(2).ok_or("count")?;
        limits.max_queued_bytes_per_link = NonZeroUsize::new(bytes).ok_or("bytes")?;
        let manager = self::manager(limits)?;
        let task = manager
            .admit("localhost", "remote.test", message.clone())
            .map_err(|error| format!("{error:?}"))?
            .ok_or("launch")?;
        assert!(matches!(
            manager.admit("localhost", "remote.test", message.clone()),
            Err(RemoteError::Busy)
        ));
        assert_eq!(task.counters.bytes.load(Ordering::Relaxed), bytes);
        task.counters.bytes.store(usize::MAX, Ordering::Relaxed);
        assert!(matches!(
            manager.admit("localhost", "remote.test", message),
            Err(RemoteError::Busy)
        ));
        task.counters.bytes.store(bytes, Ordering::Relaxed);
        drop(task.receiver);
        assert_eq!(task.counters.bytes.load(Ordering::Relaxed), 0);
        drop(task.guard);
        manager.join(Instant::now() + TIMEOUT).await?;
        Ok(())
    })
}

#[test]
fn retained_pairs_enforce_cached_precedence_and_expired_only_eviction() -> TestResult {
    run(async {
        let limits = S2sLimits {
            max_outbound_links: NonZeroUsize::new(3).ok_or("capacity")?,
            ..Default::default()
        };
        let manager = manager(limits)?;
        let now = Instant::now();
        let earlier = now.checked_sub(Duration::from_secs(10)).ok_or("clock")?;
        let live = manager
            .admit("localhost", "live.test", message().await?)
            .map_err(|error| format!("{error:?}"))?
            .ok_or("launch")?;
        {
            let mut state = manager.inner.state.lock();
            state.entries.insert(
                pair("a.test"),
                failure(earlier, Duration::from_secs(5), 4, RemoteFailure::NotFound),
            );
            state.entries.insert(
                pair("b.test"),
                failure(earlier, Duration::from_secs(5), 7, RemoteFailure::Timeout),
            );
            assert_eq!(state.retry_count("localhost", "a.test", now, 3), Ok(4));
            assert_eq!(state.entries.len(), 3);
            assert_eq!(state.retry_count("localhost", "new.test", now, 3), Ok(0));
            assert!(!state.entries.contains_key(&pair("a.test")));
            assert!(state.entries.contains_key(&pair("b.test")));
            state.entries.insert(
                pair("new.test"),
                failure(now, TIMEOUT, 1, RemoteFailure::Timeout),
            );
            assert_eq!(
                state.retry_count("localhost", "new.test", now, 3),
                Err(RemoteError::Backoff(RemoteFailure::Timeout))
            );
            assert_eq!(state.retry_count("localhost", "next.test", now, 3), Ok(0));
            state.entries.insert(
                pair("next.test"),
                failure(now, TIMEOUT, 1, RemoteFailure::NotFound),
            );
            assert_eq!(
                state.retry_count("localhost", "blocked.test", now, 3),
                Err(RemoteError::Busy)
            );
        }
        assert!(matches!(
            manager.admit("localhost", "blocked.test", message().await?),
            Err(RemoteError::Busy)
        ));
        assert!(matches!(
            manager.admit("localhost", "new.test", message().await?),
            Err(RemoteError::Backoff(RemoteFailure::Timeout))
        ));
        assert!(
            render(&manager.inner.metrics)?
                .contains("s2s_admission_rejections_total{reason=\"link_limit\"} 1")
        );
        assert!(
            manager
                .admit("localhost", "live.test", message().await?)
                .map_err(|error| format!("{error:?}"))?
                .is_none()
        );
        drop(live.receiver);
        drop(live.guard);
        manager.join(Instant::now() + TIMEOUT).await?;
        assert!(
            manager
                .inner
                .state
                .lock()
                .entries
                .values()
                .all(|entry| matches!(entry, Entry::Link(_)))
        );
        Ok(())
    })
}

#[test]
fn failure_retention_identity_and_expired_retry_use_one_slot() -> TestResult {
    run(async {
        let manager = manager(S2sLimits::default())?;
        let first = manager
            .admit("localhost", "remote.test", message().await?)
            .map_err(|error| format!("{error:?}"))?
            .ok_or("launch")?;
        let now = Instant::now();
        assert!(manager.inner.failed(
            &first.pair,
            &first.counters,
            u32::MAX,
            RemoteFailure::Timeout,
            now,
            1000
        ));
        assert!(matches!(
            manager.admit("localhost", "remote.test", message().await?),
            Err(RemoteError::Backoff(RemoteFailure::Timeout))
        ));
        {
            let mut state = manager.inner.state.lock();
            if let Some(Entry::Backoff { delay, .. }) = state.entries.get_mut(&first.pair) {
                *delay = Duration::ZERO;
            }
        }
        let second = manager
            .admit("localhost", "remote.test", message().await?)
            .map_err(|error| format!("{error:?}"))?
            .ok_or("retry")?;
        assert_eq!(second.failures, u32::MAX);
        assert_eq!(manager.inner.state.lock().entries.len(), 1);
        manager.inner.remove(&first.pair, &first.counters);
        assert!(!manager.inner.failed(
            &first.pair,
            &first.counters,
            0,
            RemoteFailure::NotFound,
            now,
            1000
        ));
        assert!(
            manager
                .inner
                .state
                .lock()
                .owns(&second.pair, &second.counters)
        );
        assert!(manager.inner.failed(
            &second.pair,
            &second.counters,
            0,
            RemoteFailure::NotFound,
            now,
            1000
        ));
        assert!(matches!(
            manager.inner.state.lock().entries.get(&second.pair),
            Some(Entry::Backoff { failures: 1, .. })
        ));
        drop(first);
        drop(second);
        manager.join(Instant::now() + TIMEOUT).await?;
        assert!(manager.inner.state.lock().entries.is_empty());
        assert!(manager.register().is_none());
        assert!(matches!(
            manager.admit("localhost", "remote.test", message().await?),
            Err(RemoteError::Stopped)
        ));
        Ok(())
    })
}

#[test]
fn jitter_is_capped_with_extreme_counts_and_elapsed_expiry() -> TestResult {
    let mut limits = S2sLimits::default();
    assert_eq!(backoff_delay(&limits, 1, 800), Duration::from_secs(24));
    assert_eq!(backoff_delay(&limits, 1, 1200), Duration::from_secs(36));
    assert_eq!(backoff_delay(&limits, 2, 1000), Duration::from_secs(60));
    assert_eq!(
        backoff_delay(&limits, u32::MAX, 1200),
        Duration::from_secs(900)
    );
    assert_eq!(
        backoff_delay(&limits, u32::MAX, 800),
        Duration::from_secs(720)
    );
    limits.failure_backoff_max_secs = NonZeroU64::new(u64::MAX).ok_or("max")?;
    limits.failure_backoff_initial_secs = limits.failure_backoff_max_secs;
    let delay = backoff_delay(&limits, u32::MAX, 1200);
    assert_eq!(delay, Duration::from_secs(u64::MAX));
    let now = Instant::now();
    assert!(now.checked_add(delay).is_none());
    let manager = manager(limits)?;
    let mut state = manager.inner.state.lock();
    state.entries.insert(
        pair("remote.test"),
        failure(now, delay, u32::MAX, RemoteFailure::Timeout),
    );
    assert_eq!(
        state.retry_count("localhost", "remote.test", now, 1),
        Err(RemoteError::Backoff(RemoteFailure::Timeout))
    );
    Ok(())
}

#[test]
fn joins_keep_the_group_through_cancellation_mutex_wait_and_drain_deadlines() -> TestResult {
    run(async {
        let manager = manager(S2sLimits::default())?;
        let guard = manager.register().ok_or("guard")?;
        {
            let mut joining = pin!(manager.join(Instant::now() + TIMEOUT));
            assert!(poll!(joining.as_mut()).is_pending());
            assert!(manager.register().is_none());
            assert!(
                matches!(manager.join(Instant::now()).await, Err(error) if error.kind() == io::ErrorKind::TimedOut)
            );
        }
        assert!(
            matches!(manager.join(Instant::now()).await, Err(error) if error.kind() == io::ErrorKind::TimedOut)
        );
        drop(guard);
        manager.join(Instant::now() + TIMEOUT).await?;
        manager.join(Instant::now() + TIMEOUT).await?;
        Ok(())
    })
}

#[test]
fn stop_interrupts_counted_component_work_and_prevents_late_registration() -> TestResult {
    run(async {
        let manager = manager(S2sLimits::default())?;
        let guard = manager.register().ok_or("guard")?;
        let stopped = manager.inner.stopped.clone();
        let (completed, completion) = oneshot::channel();
        compio::runtime::spawn(guard.run(async move {
            assert!(stopping(stopped, pending::<()>()).await.is_none());
            let _ = completed.send(());
        }))
        .detach();
        manager.stop();
        completion.await?;
        manager.join(Instant::now() + TIMEOUT).await?;
        assert!(manager.register().is_none());
        Ok(())
    })
}

#[test]
fn registered_catalog_observes_persistent_queue_link_and_failure_state() -> TestResult {
    run(async {
        let manager = manager(S2sLimits::default())?;
        let clone = manager.clone();
        let task = manager
            .admit("localhost", "remote.test", message().await?)
            .map_err(|error| format!("{error:?}"))?
            .ok_or("launch")?;
        drop(manager);
        assert!(
            render(&clone.inner.metrics)?.contains("s2s_outbound_links{state=\"connecting\"} 1")
        );
        assert!(render(&clone.inner.metrics)?.contains("s2s_outbound_queued_stanzas 1"));
        let mut failures = 9;
        ready(&task.counters, &mut failures);
        assert_eq!(failures, 0);
        assert!(render(&clone.inner.metrics)?.contains("s2s_outbound_links{state=\"ready\"} 1"));
        assert!(clone.inner.failed(
            &task.pair,
            &task.counters,
            0,
            RemoteFailure::Timeout,
            Instant::now(),
            1000
        ));
        assert!(render(&clone.inner.metrics)?.contains("s2s_outbound_links{state=\"backoff\"} 1"));
        clone.stop();
        drop(task);
        clone.join(Instant::now() + TIMEOUT).await?;
        assert!(render(&clone.inner.metrics)?.contains("s2s_outbound_links{state=\"backoff\"} 0"));
        Ok(())
    })
}

#[test]
fn disabled_and_generated_localhost_refuse_remote_admission() -> TestResult {
    run(async {
        let remote = manager(S2sLimits::default())?;
        let router = Router::new(
            remote.inner.hosts.clone(),
            LocalRouter::new(GlobalChunkAllocator),
        );
        assert!(!router.handle().federation_enabled());
        assert_eq!(
            router.handle().route_remote(message().await?),
            Err(RouterError::RemoteUnsupported)
        );
        let router = router.with_remote(remote.clone());
        assert!(router.handle().federation_enabled());
        assert!(!router.handle().federates_domain("localhost"));
        assert_eq!(
            router.handle().route_remote(message().await?),
            Err(RouterError::RemoteUnsupported)
        );
        remote.join(Instant::now() + TIMEOUT).await?;
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn bounce_delivery_uses_local_mailboxes_and_the_shared_catalog() -> TestResult {
    run(async {
        let remote = manager(S2sLimits::default())?;
        let router = Router::new(
            remote.inner.hosts.clone(),
            LocalRouter::new(GlobalChunkAllocator),
        )
        .with_remote(remote.clone());
        let handle = router.handle();
        let source = message().await?;
        let owner = lonewolf_storage::account::AccountKey::try_from(
            source.resolve()?.from()?.ok_or("sender")?.bare(),
        )?;
        let registration = handle
            .register(&owner, Some("desk"), NonZeroUsize::MIN)
            .await?;
        for xml in [
            "<message from='alice@localhost/desk' to='bob@remote.test'><body>payload</body></message>",
            "<iq from='alice@localhost/desk' to='bob@remote.test' type='get' id='request'><query xmlns='urn:test'/></iq>",
            "<presence from='alice@localhost/desk' to='bob@remote.test' type='subscribe'/>",
        ] {
            bounce(
                &handle,
                &stanza(xml).await?,
                lonewolf_xmpp::stanza::StanzaErrorCondition::RemoteServerTimeout,
            )
            .await;
            let reply = registration.recv().await.ok_or("missing bounce")?.stanza;
            assert!(reply.resolve()?.stanza_type().is_error());
            assert_eq!(
                reply.resolve()?.to()?.ok_or("to")?.resourcepart(),
                Some("desk")
            );
        }
        for xml in [
            "<presence from='alice@localhost/desk' to='bob@remote.test'/>",
            "<message from='alice@localhost/desk' to='bob@remote.test' type='error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>",
        ] {
            bounce(
                &handle,
                &stanza(xml).await?,
                lonewolf_xmpp::stanza::StanzaErrorCondition::RemoteServerTimeout,
            )
            .await;
            assert!(registration.take_queued().is_empty());
        }
        let output = render(&remote.inner.metrics)?;
        assert!(output.contains("s2s_bounces_total{condition=\"remote_server_timeout\"} 3"));
        assert!(output.contains("s2s_dropped_stanzas_total{reason=\"not_bounceable\"} 2"));
        remote
            .bounce(
                &handle,
                source.clone(),
                lonewolf_xmpp::stanza::StanzaErrorCondition::ResourceConstraint,
            )
            .map_err(|error| format!("{error:?}"))?;
        let guard = remote.register().ok_or("bounce guard")?;
        remote.stop();
        assert!(remote.register().is_none());
        assert!(matches!(
            remote.bounce(
                &handle,
                source,
                lonewolf_xmpp::stanza::StanzaErrorCondition::ResourceConstraint
            ),
            Err(RemoteError::Stopped)
        ));
        drop(guard);
        remote.join(Instant::now() + TIMEOUT).await?;
        assert!(
            render(&remote.inner.metrics)?
                .contains("s2s_dropped_stanzas_total{reason=\"shutdown\"} 1")
        );
        assert!(
            render(&remote.inner.metrics)?
                .contains("s2s_bounces_total{condition=\"resource_constraint\"} 1")
        );
        assert!(
            registration
                .recv()
                .await
                .ok_or("detached bounce")?
                .stanza
                .resolve()?
                .stanza_type()
                .is_error()
        );
        drop(registration);
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn jitter_rejects_biased_draws_and_uses_nominal_delay_on_source_failure() {
    assert_eq!(draw_jitter(|_| false), 1000);
    for (draw, expected) in [(0_u16, 800), (400, 1200)] {
        assert_eq!(
            draw_jitter(|bytes| {
                bytes.copy_from_slice(&draw.to_ne_bytes());
                true
            }),
            expected
        );
    }
    let mut draws = [u16::MAX, 400].into_iter();
    assert_eq!(
        draw_jitter(|bytes| {
            let Some(draw) = draws.next() else {
                return false;
            };
            bytes.copy_from_slice(&draw.to_ne_bytes());
            true
        }),
        1200
    );
    assert!(draws.next().is_none());
}

#[test]
fn eviction_uses_logical_expiry_instead_of_failure_start_time() -> TestResult {
    let manager = manager(S2sLimits::default())?;
    let now = Instant::now();
    let mut state = manager.inner.state.lock();
    state.entries.insert(
        pair("earlier-start.test"),
        failure(
            now.checked_sub(Duration::from_secs(20)).ok_or("clock")?,
            Duration::from_secs(19),
            3,
            RemoteFailure::Timeout,
        ),
    );
    state.entries.insert(
        pair("earlier-expiry.test"),
        failure(
            now.checked_sub(Duration::from_secs(10)).ok_or("clock")?,
            Duration::from_secs(5),
            7,
            RemoteFailure::NotFound,
        ),
    );
    assert_eq!(state.retry_count("localhost", "new.test", now, 2), Ok(0));
    assert!(!state.entries.contains_key(&pair("earlier-expiry.test")));
    assert!(state.entries.contains_key(&pair("earlier-start.test")));
    Ok(())
}
