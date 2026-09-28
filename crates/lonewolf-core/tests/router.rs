// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::future::Future;
use std::io;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use compio::runtime::Runtime;
use compio::time::timeout;
use lonewolf_core::config::Config;
use lonewolf_core::hosts::Hosts;
use lonewolf_core::router::local::LocalRouter;
use lonewolf_core::router::{RoutedStanza, Router, RouterError};
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ArenaConfig, GlobalChunkAllocator};
use lonewolf_util::core_dispatcher::CoreDispatcher;
use lonewolf_util::pool::{PoolConfig, PooledChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::{ParserConfig, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::StanzaKind;

type TestResult = Result<(), Box<dyn Error>>;
const TIMEOUT: Duration = Duration::from_secs(5);
const STANZA_BYTES: NonZeroUsize = NonZeroUsize::new(4096).unwrap();

fn run_test(test: impl Future<Output = TestResult>) -> TestResult {
    Runtime::new()?.block_on(timeout(TIMEOUT, test))?
}

async fn setup() -> Result<(Router<GlobalChunkAllocator>, CoreDispatcher), Box<dyn Error>> {
    let two = NonZeroUsize::MIN.saturating_add(1);
    let dispatcher = match CoreDispatcher::new(two, two) {
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => {
            CoreDispatcher::new(NonZeroUsize::MIN, two)?
        }
        result => result?,
    };
    let config = Config::default();
    let hosts = Hosts::new(&config.hosts, config.xmpp.default_host.as_deref())?;
    let local = LocalRouter::start(&dispatcher.handle(), GlobalChunkAllocator).await?;
    let router = Router::new(hosts, local);
    Ok((router, dispatcher))
}

fn account(value: &str) -> Result<AccountKey, Box<dyn Error>> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let jid = Jid::parse_in(value, &mut arena)?;
    Ok(AccountKey::try_from(jid.resolve(&arena)?)?)
}

async fn parse_stanza(xml: &str) -> Result<RoutedStanza<GlobalChunkAllocator>, Box<dyn Error>> {
    let xml = format!(
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' version='1.0'>{xml}"
    );
    let mut parser = XmppParser::new(
        xml.as_bytes(),
        ParserConfig {
            max_stanza_bytes: STANZA_BYTES,
            arena: ArenaConfig::default(),
        },
        GlobalChunkAllocator,
    );
    assert!(matches!(
        parser.next_event().await?,
        Some(StreamEvent::StreamStart { .. })
    ));
    match parser.next_event().await? {
        Some(StreamEvent::Stanza(parsed)) => Ok(RoutedStanza::from_parsed(parsed)),
        _ => Err("expected a stanza".into()),
    }
}

async fn stanza(to: &str) -> Result<RoutedStanza<GlobalChunkAllocator>, Box<dyn Error>> {
    parse_stanza(&format!("<message to='{to}'><body>Hello</body></message>")).await
}

async fn presence(resource: &str) -> Result<RoutedStanza<GlobalChunkAllocator>, Box<dyn Error>> {
    parse_stanza(&format!("<presence from='alice@localhost/{resource}'/>")).await
}

async fn unavailable_presence(
    resource: &str,
) -> Result<RoutedStanza<GlobalChunkAllocator>, Box<dyn Error>> {
    parse_stanza(&format!(
        "<presence from='alice@localhost/{resource}' type='unavailable'/>"
    ))
    .await
}

#[test]
fn registration_uses_one_account_shard_across_handles() -> TestResult {
    run_test(async {
        let (router, dispatcher) = setup().await?;
        let alice = account("alice@localhost")?;
        let first = router.handle();
        let second = router.handle();
        let desk = first
            .register(&alice, Some("desk"), NonZeroUsize::new(2).unwrap())
            .await?;
        assert_eq!(desk.full_jid(), "alice@localhost/desk");

        assert!(matches!(
            second
                .register(&alice, Some("phone"), NonZeroUsize::MIN)
                .await,
            Err(RouterError::ResourceLimit)
        ));

        let duplicate = second
            .register(&alice, Some("desk"), NonZeroUsize::new(2).unwrap())
            .await?;
        assert_ne!(duplicate.resource(), "desk");
        assert!(duplicate.full_jid().starts_with("alice@localhost/"));

        assert!(matches!(
            first
                .register(&alice, None, NonZeroUsize::new(2).unwrap())
                .await,
            Err(RouterError::ResourceLimit)
        ));

        drop(desk);
        let reused = second
            .register(&alice, Some("desk"), NonZeroUsize::new(2).unwrap())
            .await?;
        assert_eq!(reused.resource(), "desk");
        drop(duplicate);
        drop(reused);
        router.shutdown().await?;
        dispatcher.shutdown(TIMEOUT).await?;
        Ok(())
    })
}

#[test]
fn resource_validation_uses_router_allocator() -> TestResult {
    run_test(async {
        let dispatcher = CoreDispatcher::new(NonZeroUsize::MIN, NonZeroUsize::MIN)?;
        let pool = Arc::new(PooledChunkAllocator::try_new(PoolConfig {
            total_bytes: NonZeroUsize::new(8 * 1024 * 1024).unwrap(),
            shards_per_bucket: NonZeroUsize::MIN,
        })?);
        let config = Config::default();
        let hosts = Hosts::new(&config.hosts, config.xmpp.default_host.as_deref())?;
        let local = LocalRouter::start(&dispatcher.handle(), Arc::clone(&pool)).await?;
        let router = Router::new(hosts, local);
        let before = pool.stats().buckets[0].allocation_count;
        let alice = account("alice@localhost")?;
        let registration = router
            .handle()
            .register(&alice, Some("desk"), NonZeroUsize::MIN)
            .await?;
        assert_eq!(registration.resource(), "desk");
        assert_eq!(pool.stats().buckets[0].allocation_count, before + 1);
        drop(registration);
        router.shutdown().await?;
        dispatcher.shutdown(TIMEOUT).await?;
        Ok(())
    })
}

#[test]
fn generated_resources_are_unique_random_identifiers() -> TestResult {
    run_test(async {
        let (router, dispatcher) = setup().await?;
        let alice = account("alice@localhost")?;
        let handle = router.handle();
        let first = handle
            .register(&alice, None, NonZeroUsize::new(2).unwrap())
            .await?;
        let second = handle
            .register(&alice, None, NonZeroUsize::new(2).unwrap())
            .await?;
        assert_ne!(first.resource(), second.resource());
        for resource in [first.resource(), second.resource()] {
            assert_eq!(resource.len(), 35);
            assert!(resource.starts_with("lw-"));
            assert!(resource[3..].bytes().all(|byte| byte.is_ascii_hexdigit()));
        }
        drop(first);
        drop(second);
        router.shutdown().await?;
        dispatcher.shutdown(TIMEOUT).await?;
        Ok(())
    })
}

#[test]
fn concurrent_registration_on_different_workers_is_atomic() -> TestResult {
    run_test(async {
        let (router, dispatcher) = setup().await?;
        let workers = dispatcher.handle();
        let alice = account("alice@localhost")?;
        let first_router = router.handle();
        let first_account = alice.clone();
        let first = workers
            .dispatch_at(0, move |_| async move {
                first_router
                    .register(&first_account, Some("desk"), NonZeroUsize::MIN)
                    .await
            })
            .await?;
        let second_router = router.handle();
        let second = workers
            .dispatch_at(workers.worker_count() - 1, move |_| async move {
                second_router
                    .register(&alice, Some("desk"), NonZeroUsize::MIN)
                    .await
            })
            .await?;
        let first = first.await?;
        let second = second.await?;
        assert_eq!(first.is_ok() as u8 + second.is_ok() as u8, 1);
        assert!(matches!(first, Ok(_) | Err(RouterError::ResourceLimit)));
        assert!(matches!(second, Ok(_) | Err(RouterError::ResourceLimit)));

        router.shutdown().await?;
        dispatcher.shutdown(TIMEOUT).await?;
        Ok(())
    })
}

#[test]
fn exact_delivery_respects_mailbox_capacity_and_lease() -> TestResult {
    run_test(async {
        let (router, dispatcher) = setup().await?;
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let registration = handle
            .register(&alice, Some("desk"), NonZeroUsize::MIN)
            .await?;
        for _ in 0..64 {
            handle
                .route_full(stanza("alice@localhost/desk").await?)
                .await?;
        }
        assert!(matches!(
            handle
                .route_full(stanza("alice@localhost/desk").await?)
                .await,
            Err(RouterError::Busy)
        ));
        assert_eq!(
            registration.recv().await.ok_or("closed")?.resolve()?.kind(),
            StanzaKind::Message
        );
        handle
            .route_full(stanza("alice@localhost/desk").await?)
            .await?;
        drop(registration);
        assert!(matches!(
            handle
                .route_full(stanza("alice@localhost/desk").await?)
                .await,
            Err(RouterError::NotFound)
        ));

        router.shutdown().await?;
        dispatcher.shutdown(TIMEOUT).await?;
        Ok(())
    })
}

#[test]
fn invalid_and_remote_destinations_are_not_routed_locally() -> TestResult {
    run_test(async {
        let (router, dispatcher) = setup().await?;
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        assert!(matches!(
            handle.register(&alice, Some(""), NonZeroUsize::MIN).await,
            Err(RouterError::InvalidResource)
        ));

        assert!(matches!(
            handle.route_full(stanza("alice@localhost").await?).await,
            Err(RouterError::InvalidTarget)
        ));
        assert!(matches!(
            handle
                .route_full(stanza("alice@example.com/desk").await?)
                .await,
            Err(RouterError::RemoteUnsupported)
        ));

        router.shutdown().await?;
        dispatcher.shutdown(TIMEOUT).await?;
        Ok(())
    })
}

#[test]
fn full_presence_mailbox_retires_recipient_and_notifies_peers() -> TestResult {
    run_test(async {
        let (router, dispatcher) = setup().await?;
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let desk = handle
            .register(&alice, Some("desk"), NonZeroUsize::new(2).unwrap())
            .await?;
        let phone = handle
            .register(&alice, Some("phone"), NonZeroUsize::new(2).unwrap())
            .await?;
        desk.set_presence(
            Some(0),
            presence("desk").await?,
            Some(unavailable_presence("desk").await?),
        )
        .await?;
        desk.recv().await.ok_or("missing own presence")?;
        phone
            .set_presence(
                Some(0),
                presence("phone").await?,
                Some(unavailable_presence("phone").await?),
            )
            .await?;
        phone.recv().await.ok_or("missing presence snapshot")?;
        phone.recv().await.ok_or("missing own presence")?;
        desk.recv().await.ok_or("missing peer presence")?;

        for _ in 0..64 {
            handle
                .route_full(stanza("alice@localhost/phone").await?)
                .await?;
        }
        desk.set_presence(
            Some(1),
            presence("desk").await?,
            Some(unavailable_presence("desk").await?),
        )
        .await?;
        desk.recv().await.ok_or("missing updated presence")?;
        let unavailable = desk.recv().await.ok_or("missing peer unavailable")?;
        assert_eq!(
            unavailable
                .resolve()?
                .from()?
                .ok_or("missing sender")?
                .as_str(),
            "alice@localhost/phone"
        );
        assert!(matches!(
            handle
                .route_full(stanza("alice@localhost/phone").await?)
                .await,
            Err(RouterError::NotFound)
        ));
        for _ in 0..64 {
            phone.recv().await.ok_or("missing queued message")?;
        }
        assert!(phone.recv().await.is_none());

        drop(desk);
        drop(phone);
        router.shutdown().await?;
        dispatcher.shutdown(TIMEOUT).await?;
        Ok(())
    })
}

#[test]
fn full_unavailable_mailbox_retires_recipient() -> TestResult {
    run_test(async {
        let (router, dispatcher) = setup().await?;
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let desk = handle
            .register(&alice, Some("desk"), NonZeroUsize::new(2).unwrap())
            .await?;
        let phone = handle
            .register(&alice, Some("phone"), NonZeroUsize::new(2).unwrap())
            .await?;
        desk.set_presence(
            Some(0),
            presence("desk").await?,
            Some(unavailable_presence("desk").await?),
        )
        .await?;
        desk.recv().await.ok_or("missing own presence")?;
        phone
            .set_presence(Some(0), presence("phone").await?, None)
            .await?;
        phone.recv().await.ok_or("missing presence snapshot")?;
        phone.recv().await.ok_or("missing own presence")?;
        desk.recv().await.ok_or("missing peer presence")?;
        for _ in 0..64 {
            handle
                .route_full(stanza("alice@localhost/phone").await?)
                .await?;
        }

        drop(desk);
        assert!(matches!(
            handle
                .route_full(stanza("alice@localhost/phone").await?)
                .await,
            Err(RouterError::NotFound)
        ));
        for _ in 0..64 {
            phone.recv().await.ok_or("missing queued message")?;
        }
        assert!(phone.recv().await.is_none());

        drop(phone);
        router.shutdown().await?;
        dispatcher.shutdown(TIMEOUT).await?;
        Ok(())
    })
}
