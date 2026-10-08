// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::future::Future;
use std::io;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::config::Config;
use crate::hosts::Hosts;
use crate::router::local::{LocalRouter, RetireCause};
use crate::router::{Registration, RoutedStanza, Router, RouterError};
use compio::runtime::Runtime;
use compio::time::timeout;
use lonewolf_extension::delivery::SessionTag;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ArenaConfig, GlobalChunkAllocator};
use lonewolf_util::core_dispatcher::CoreDispatcher;
use lonewolf_util::pool::{PoolConfig, PooledChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::{ParserConfig, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::{Element, IqType, Stanza, StanzaKind, StanzaNamespace, StanzaType};

type TestResult = Result<(), Box<dyn Error>>;
type TestRosterPush = Result<RoutedStanza<GlobalChunkAllocator>, RouterError>;
const TIMEOUT: Duration = Duration::from_secs(5);
const STANZA_BYTES: NonZeroUsize = NonZeroUsize::new(4096).unwrap();

fn run_test(test: impl Future<Output = TestResult>) -> TestResult {
    Runtime::new()?.block_on(timeout(TIMEOUT, test))?
}

#[test]
fn presence_errors_keep_exact_and_available_audiences_and_presence_state() -> TestResult {
    run_test(async {
        let router = setup()?;
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let limit = NonZeroUsize::new(3).ok_or("zero limit")?;
        let desk = handle.register(&alice, Some("desk"), limit).await?;
        let phone = handle.register(&alice, Some("phone"), limit).await?;
        let tablet = handle.register(&alice, Some("tablet"), limit).await?;
        for (resource, priority) in [(&phone, -1), (&tablet, 5)] {
            resource
                .handle()
                .set_presence(
                    Some(priority),
                    identified_presence(resource.resource(), resource.resource()).await?,
                    Some(unavailable_presence(resource.resource()).await?),
                )
                .await?;
        }
        phone.take_queued();
        for resource in [&desk, &phone, &tablet] {
            directed_grant(resource, "bob@localhost/desk", true).await?;
        }
        let full = parse_stanza("<presence from='bob@localhost/desk' to='alice@localhost/desk' type='error' id='full'><priority>127</priority><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>").await?;
        handle.route_presence_error(full).await?;
        assert_eq!(receive_routed(&desk).await?.resolve()?.id()?, Some("full"));
        assert!(phone.take_queued().is_empty());
        assert!(tablet.take_queued().is_empty());
        let bare = parse_stanza("<presence from='bob@localhost/desk' to='alice@localhost' type='error' id='bare'><priority>127</priority><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>").await?;
        assert_eq!(
            handle.route_presence(bare.clone()).await,
            Err(RouterError::InvalidTarget)
        );
        handle.route_presence_error(bare).await?;
        assert!(desk.take_queued().is_empty());
        for resource in [&phone, &tablet] {
            assert_eq!(
                receive_routed(resource).await?.resolve()?.id()?,
                Some("bare")
            );
        }
        let snapshots = handle.local.presence_snapshot(&alice).await?;
        assert_eq!(snapshots.len(), 2);
        let mut ids = [snapshots[0].resolve()?.id()?, snapshots[1].resolve()?.id()?];
        ids.sort();
        assert_eq!(ids, [Some("phone"), Some("tablet")]);
        for resource in [&desk, &phone, &tablet] {
            assert!(has_grant(&handle, &alice, resource.resource(), "bob@localhost/desk").await?);
        }
        handle
            .route_message(stanza("alice@localhost").await?)
            .await?;
        receive_routed(&tablet).await?;
        assert!(phone.take_queued().is_empty());
        drop(tablet);
        assert_eq!(
            handle.route_message(stanza("alice@localhost").await?).await,
            Err(RouterError::Offline)
        );
        drop((desk, phone));
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn presence_errors_use_bounded_mailboxes_and_keep_replacement_registrations() -> TestResult {
    run_test(async {
        let router = setup()?;
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let desk = handle
            .register(&alice, Some("desk"), NonZeroUsize::MIN)
            .await?;
        desk.handle()
            .set_presence(Some(0), presence("desk").await?, None)
            .await?;
        let bob = handle
            .register(&account("bob@localhost")?, Some("desk"), NonZeroUsize::MIN)
            .await?;
        for _ in 0..64 {
            handle
                .route_full(stanza("alice@localhost/desk").await?)
                .await?;
        }
        let full = parse_stanza(
            "<presence from='bob@localhost/desk' to='alice@localhost/desk' type='error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>",
        )
        .await?;
        assert_eq!(
            handle.route_presence_error(full.clone()).await,
            Err(RouterError::Busy)
        );
        assert!(desk.liveness().is_alive());
        let bare =
            parse_stanza("<presence from='bob@localhost/desk' to='alice@localhost' type='error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>")
                .await?;
        assert_eq!(
            handle.route_presence_error(bare).await,
            Err(RouterError::Busy)
        );
        assert!(!desk.liveness().is_alive());
        assert_eq!(desk.take_queued().len(), 64);
        assert!(desk.recv().await.is_none());
        assert!(bob.take_queued().is_empty());
        assert_eq!(
            handle.route_presence_error(full.clone()).await,
            Err(RouterError::NotFound)
        );
        let replacement = handle
            .register(&alice, Some("desk"), NonZeroUsize::MIN)
            .await?;
        drop(desk);
        handle.route_presence_error(full).await?;
        let delivered = receive_routed(&replacement).await?;
        assert_eq!(
            delivered.resolve()?.stanza_type(),
            StanzaType::Presence(lonewolf_xmpp::stanza::PresenceType::Error)
        );
        assert!(bob.take_queued().is_empty());
        drop((replacement, bob));
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn absent_account_message_targets_distinguish_offline_from_missing_resources() -> TestResult {
    run_test(async {
        let router = setup()?;
        let handle = router.handle();
        for (to, kind, expected) in [
            ("alice@localhost", "normal", RouterError::Offline),
            ("alice@localhost", "chat", RouterError::Offline),
            ("alice@localhost", "headline", RouterError::Offline),
            ("alice@localhost/missing", "normal", RouterError::NotFound),
            ("alice@localhost/missing", "chat", RouterError::Offline),
            ("alice@localhost/missing", "headline", RouterError::NotFound),
            ("localhost", "normal", RouterError::NotFound),
        ] {
            let stanza = parse_stanza(&format!("<message to='{to}' type='{kind}'/>")).await?;
            assert_eq!(
                handle.route_message(stanza).await,
                Err(expected),
                "{to} {kind}"
            );
        }
        let error = parse_stanza("<message to='alice@localhost/missing' type='error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>").await?;
        assert_eq!(
            handle.route_message(error).await,
            Err(RouterError::NotFound)
        );
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn unavailable_and_negative_siblings_keep_full_normal_targets_missing() -> TestResult {
    run_test(async {
        let router = setup()?;
        let handle = router.handle();
        let owner = account("alice@localhost")?;
        let resource = handle
            .register(&owner, Some("desk"), NonZeroUsize::MIN)
            .await?;
        for priority in [None, Some(-1)] {
            resource
                .handle()
                .set_presence(
                    priority,
                    presence("desk").await?,
                    Some(unavailable_presence("desk").await?),
                )
                .await?;
            for (to, kind, expected) in [
                ("alice@localhost", "normal", RouterError::Offline),
                ("alice@localhost", "chat", RouterError::Offline),
                ("alice@localhost", "headline", RouterError::Offline),
                ("alice@localhost/missing", "normal", RouterError::NotFound),
                ("alice@localhost/missing", "chat", RouterError::Offline),
                ("alice@localhost/missing", "headline", RouterError::NotFound),
                (
                    "alice@localhost/missing",
                    "groupchat",
                    RouterError::NotFound,
                ),
            ] {
                let stanza = parse_stanza(&format!("<message to='{to}' type='{kind}'/>")).await?;
                assert_eq!(handle.route_message(stanza).await, Err(expected));
            }
            assert!(resource.take_queued().is_empty());
        }
        drop(resource);
        assert_eq!(
            handle.route_message(stanza("alice@localhost").await?).await,
            Err(RouterError::Offline)
        );
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn missing_normal_resource_does_not_fall_back_to_an_eligible_sibling() -> TestResult {
    run_test(async {
        let router = setup()?;
        let handle = router.handle();
        let owner = account("alice@localhost")?;
        let resource = handle
            .register(&owner, Some("desk"), NonZeroUsize::MIN)
            .await?;
        resource
            .handle()
            .set_presence(
                Some(0),
                presence("desk").await?,
                Some(unavailable_presence("desk").await?),
            )
            .await?;
        assert_eq!(
            handle
                .route_message(stanza("alice@localhost/missing").await?)
                .await,
            Err(RouterError::NotFound)
        );
        let chat = parse_stanza("<message to='alice@localhost/missing' type='chat'/>").await?;
        handle.route_message(chat).await?;
        assert_eq!(
            receive_routed(&resource)
                .await?
                .resolve()?
                .to()?
                .ok_or("missing target")?
                .as_str(),
            "alice@localhost/missing"
        );
        drop(resource);
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn full_eligible_mailboxes_remain_busy_instead_of_offline() -> TestResult {
    run_test(async {
        let router = setup()?;
        let handle = router.handle();
        let owner = account("alice@localhost")?;
        let resource = handle
            .register(&owner, Some("desk"), NonZeroUsize::MIN)
            .await?;
        resource
            .handle()
            .set_presence(
                Some(0),
                presence("desk").await?,
                Some(unavailable_presence("desk").await?),
            )
            .await?;
        for _ in 0..64 {
            handle
                .route_full(stanza("alice@localhost/desk").await?)
                .await?;
        }
        for kind in ["normal", "chat", "headline"] {
            let stanza =
                parse_stanza(&format!("<message to='alice@localhost' type='{kind}'/>")).await?;
            assert_eq!(handle.route_message(stanza).await, Err(RouterError::Busy));
        }
        assert_eq!(
            handle
                .route_message(stanza("alice@localhost/missing").await?)
                .await,
            Err(RouterError::NotFound)
        );
        drop(resource);
        router.shutdown().await?;
        Ok(())
    })
}

fn setup() -> Result<Router<GlobalChunkAllocator>, Box<dyn Error>> {
    let config = Config::default();
    let hosts = Hosts::new(&config.hosts, config.xmpp.default_host.as_deref())?;
    Ok(Router::new(hosts, LocalRouter::new(GlobalChunkAllocator)))
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

async fn identified_presence(
    resource: &str,
    id: &str,
) -> Result<RoutedStanza<GlobalChunkAllocator>, Box<dyn Error>> {
    parse_stanza(&format!(
        "<presence from='alice@localhost/{resource}' id='{id}'/>"
    ))
    .await
}

async fn unavailable_presence(
    resource: &str,
) -> Result<RoutedStanza<GlobalChunkAllocator>, Box<dyn Error>> {
    parse_stanza(&format!(
        "<presence from='alice@localhost/{resource}' type='unavailable'/>"
    ))
    .await
}

async fn receive_routed(
    registration: &Registration<GlobalChunkAllocator>,
) -> Result<RoutedStanza<GlobalChunkAllocator>, Box<dyn Error>> {
    registration
        .recv()
        .await
        .ok_or_else(|| "closed resource mailbox".into())
}

fn roster_push(to: &str, id: &str) -> TestRosterPush {
    let mut arena = Arena::try_new(ArenaConfig::default()).map_err(|_| RouterError::Unavailable)?;
    let item = Element::builder_in("item", "jabber:iq:roster", &mut arena)
        .map_err(|_| RouterError::Unavailable)?
        .attribute("jid", "", "bob@localhost")
        .map_err(|_| RouterError::Unavailable)?
        .build()
        .map_err(|_| RouterError::Unavailable)?;
    let query = Element::builder_in("query", "jabber:iq:roster", &mut arena)
        .map_err(|_| RouterError::Unavailable)?
        .child(item)
        .map_err(|_| RouterError::Unavailable)?
        .build()
        .map_err(|_| RouterError::Unavailable)?;
    let to = Jid::parse_in(to, &mut arena).map_err(|_| RouterError::InvalidTarget)?;
    let stanza = Stanza::builder_in(
        StanzaType::Iq(IqType::Set),
        StanzaNamespace::Client,
        &mut arena,
    )
    .id(Some(id))
    .map_err(|_| RouterError::Unavailable)?
    .to(Some(to))
    .map_err(|_| RouterError::Unavailable)?
    .child(query)
    .map_err(|_| RouterError::Unavailable)?
    .build()
    .map_err(|_| RouterError::Unavailable)?;
    Ok(RoutedStanza::from_parts(stanza, arena))
}

fn roster_pushes() -> impl FnMut(&str) -> TestRosterPush + Send {
    let mut next_id = 0;
    move |to| {
        let id = format!("push-{next_id}");
        next_id += 1;
        roster_push(to, &id)
    }
}

#[test]
fn registration_uses_one_account_shard_across_handles() -> TestResult {
    run_test(async {
        let router = setup()?;
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
        Ok(())
    })
}

#[test]
fn retiring_an_account_ends_every_session_and_frees_its_resources() -> TestResult {
    run_test(async {
        let router = setup()?;
        let alice = account("alice@localhost")?;
        let bob = account("bob@localhost")?;
        let handle = router.handle();
        let desk = handle
            .register(&alice, Some("desk"), NonZeroUsize::new(2).unwrap())
            .await?;
        let phone = handle
            .register(&alice, Some("phone"), NonZeroUsize::new(2).unwrap())
            .await?;
        let bob_desk = handle
            .register(&bob, Some("desk"), NonZeroUsize::new(2).unwrap())
            .await?;
        desk.handle()
            .set_presence(
                Some(0),
                presence("desk").await?,
                Some(unavailable_presence("desk").await?),
            )
            .await?;

        handle.retire_account(&alice).await?;
        let retired = desk.wait_retired().await?;
        assert_eq!(retired.cause, RetireCause::AccountDeleted);
        assert!(retired.unavailable.is_some());
        let retired = phone.wait_retired().await?;
        assert_eq!(retired.cause, RetireCause::AccountDeleted);
        assert!(retired.unavailable.is_none());
        assert!(desk.recv().await.is_none());
        assert!(phone.recv().await.is_none());
        assert!(matches!(
            handle
                .route_full(stanza("alice@localhost/desk").await?)
                .await,
            Err(RouterError::NotFound)
        ));
        assert_eq!(handle.local.withdrawal_snapshot(&alice).await?.len(), 1);
        assert!(desk.end_presence().await?.unavailable.is_some());
        desk.finish_presence().await?;
        assert!(handle.local.withdrawal_snapshot(&alice).await?.is_empty());

        handle
            .route_full(stanza("bob@localhost/desk").await?)
            .await?;
        receive_routed(&bob_desk).await?;
        let replacement = handle
            .register(&alice, Some("desk"), NonZeroUsize::new(2).unwrap())
            .await?;
        assert_eq!(replacement.resource(), "desk");
        handle.retire_account(&alice).await?;
        handle.retire_account(&account("carol@localhost")?).await?;
        drop(replacement);
        drop(desk);
        drop(phone);
        drop(bob_desk);
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn resource_validation_uses_router_allocator() -> TestResult {
    run_test(async {
        let pool = Arc::new(PooledChunkAllocator::try_new(PoolConfig {
            total_bytes: NonZeroUsize::new(8 * 1024 * 1024).unwrap(),
            shards_per_bucket: NonZeroUsize::MIN,
        })?);
        let config = Config::default();
        let hosts = Hosts::new(&config.hosts, config.xmpp.default_host.as_deref())?;
        let local = LocalRouter::new(Arc::clone(&pool));
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
        Ok(())
    })
}

#[test]
fn generated_resources_are_unique_random_identifiers() -> TestResult {
    run_test(async {
        let router = setup()?;
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
        Ok(())
    })
}

#[test]
fn concurrent_registration_on_different_workers_is_atomic() -> TestResult {
    run_test(async {
        let two = NonZeroUsize::MIN.saturating_add(1);
        let dispatcher = match CoreDispatcher::new(two, two) {
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => {
                CoreDispatcher::new(NonZeroUsize::MIN, two)?
            }
            result => result?,
        };
        let router = setup()?;
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
        let router = setup()?;
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
            receive_routed(&registration).await?.resolve()?.kind(),
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
        Ok(())
    })
}

#[test]
fn roster_push_reaches_only_interested_resources() -> TestResult {
    run_test(async {
        let router = setup()?;
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let limit = NonZeroUsize::new(3).ok_or("zero resource limit")?;
        let desk = handle.register(&alice, Some("desk"), limit).await?;
        let phone = handle.register(&alice, Some("phone"), limit).await?;
        let tablet = handle.register(&alice, Some("tablet"), limit).await?;
        desk.handle().tag(SessionTag::Interested).await?;
        tablet.handle().tag(SessionTag::Interested).await?;

        handle
            .route_to_tagged(&alice, SessionTag::Interested, roster_pushes())
            .await?;

        let desk_push = receive_routed(&desk).await?;
        let tablet_push = receive_routed(&tablet).await?;
        let desk_view = desk_push.resolve()?;
        let tablet_view = tablet_push.resolve()?;
        assert_eq!(
            desk_view.to()?.ok_or("missing desk target")?.as_str(),
            "alice@localhost/desk"
        );
        assert_eq!(
            tablet_view.to()?.ok_or("missing tablet target")?.as_str(),
            "alice@localhost/tablet"
        );
        assert_ne!(desk_view.id()?, tablet_view.id()?);

        handle
            .route_full(stanza("alice@localhost/phone").await?)
            .await?;
        assert_eq!(
            receive_routed(&phone).await?.resolve()?.kind(),
            StanzaKind::Message
        );

        drop(desk);
        drop(phone);
        drop(tablet);
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn roster_push_retires_an_interested_resource_with_a_full_mailbox() -> TestResult {
    run_test(async {
        let router = setup()?;
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let limit = NonZeroUsize::new(2).ok_or("zero resource limit")?;
        let desk = handle.register(&alice, Some("desk"), limit).await?;
        let phone = handle.register(&alice, Some("phone"), limit).await?;
        desk.handle().tag(SessionTag::Interested).await?;
        phone.handle().tag(SessionTag::Interested).await?;
        for _ in 0..64 {
            handle
                .route_full(stanza("alice@localhost/phone").await?)
                .await?;
        }

        handle
            .route_to_tagged(&alice, SessionTag::Interested, roster_pushes())
            .await?;

        assert_eq!(
            receive_routed(&desk).await?.resolve()?.kind(),
            StanzaKind::Iq
        );
        assert!(matches!(
            handle
                .route_full(stanza("alice@localhost/phone").await?)
                .await,
            Err(RouterError::NotFound)
        ));
        for _ in 0..64 {
            assert_eq!(
                receive_routed(&phone).await?.resolve()?.kind(),
                StanzaKind::Message
            );
        }
        assert!(phone.recv().await.is_none());

        drop(desk);
        drop(phone);
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn roster_push_build_failure_retires_every_interested_resource() -> TestResult {
    run_test(async {
        let router = setup()?;
        let handle = router.handle();
        let limit = NonZeroUsize::new(3).ok_or("zero resource limit")?;

        for (username, fail_at) in [("alice", 0), ("bob", 1)] {
            let account = account(&format!("{username}@localhost"))?;
            let desk = handle.register(&account, Some("desk"), limit).await?;
            let phone = handle.register(&account, Some("phone"), limit).await?;
            let tablet = handle.register(&account, Some("tablet"), limit).await?;
            desk.handle().tag(SessionTag::Interested).await?;
            phone.handle().tag(SessionTag::Interested).await?;
            tablet.handle().tag(SessionTag::Interested).await?;

            let mut calls = 0;
            let result = handle
                .route_to_tagged(&account, SessionTag::Interested, move |to| {
                    if calls == fail_at {
                        return Err(RouterError::Unavailable);
                    }
                    calls += 1;
                    roster_push(to, "push")
                })
                .await;
            assert_eq!(result, Err(RouterError::Unavailable));

            for resource in ["desk", "phone", "tablet"] {
                let to = format!("{username}@localhost/{resource}");
                assert_eq!(
                    handle.route_full(stanza(&to).await?).await,
                    Err(RouterError::NotFound)
                );
            }
            assert!(desk.recv().await.is_none());
            assert!(phone.recv().await.is_none());
            assert!(tablet.recv().await.is_none());
        }

        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn disconnected_interested_resource_is_removed_before_roster_push() -> TestResult {
    run_test(async {
        let router = setup()?;
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let desk = handle
            .register(&alice, Some("desk"), NonZeroUsize::MIN)
            .await?;
        desk.handle().tag(SessionTag::Interested).await?;
        drop(desk);

        let calls = Arc::new(AtomicUsize::new(0));
        handle
            .route_to_tagged(&alice, SessionTag::Interested, {
                let calls = Arc::clone(&calls);
                move |to| {
                    calls.fetch_add(1, Ordering::Relaxed);
                    roster_push(to, "push")
                }
            })
            .await?;
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert!(matches!(
            handle
                .route_full(stanza("alice@localhost/desk").await?)
                .await,
            Err(RouterError::NotFound)
        ));

        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn invalid_and_remote_destinations_are_not_routed_locally() -> TestResult {
    run_test(async {
        let router = setup()?;
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
        Ok(())
    })
}

#[test]
fn presence_eligibility_only_changes_when_a_resource_enters_nonnegative_priority() -> TestResult {
    run_test(async {
        let router = setup()?;
        let handle = router.handle();
        let owner = account("alice@localhost")?;
        for (old, new, expected) in [
            (None, Some(0), true),
            (None, Some(-1), false),
            (Some(-1), Some(0), true),
            (Some(5), Some(3), false),
            (Some(0), None, false),
            (Some(0), Some(-1), false),
        ] {
            let registration = handle
                .register(&owner, Some("desk"), NonZeroUsize::MIN)
                .await?;
            if old.is_some() {
                registration
                    .handle()
                    .set_presence(old, presence("desk").await?, None)
                    .await?;
            }
            let change = registration
                .handle()
                .set_presence(new, presence("desk").await?, None)
                .await?;
            assert_eq!(change.became_eligible, expected, "{old:?} -> {new:?}");
            drop(registration);
        }
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn full_presence_mailbox_retires_recipient_and_notifies_peers() -> TestResult {
    run_test(async {
        let router = setup()?;
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let desk = handle
            .register(&alice, Some("desk"), NonZeroUsize::new(2).unwrap())
            .await?;
        let phone = handle
            .register(&alice, Some("phone"), NonZeroUsize::new(2).unwrap())
            .await?;
        let became_available = desk
            .handle()
            .set_presence(
                Some(0),
                presence("desk").await?,
                Some(unavailable_presence("desk").await?),
            )
            .await?;
        assert!(became_available.became_available);
        assert!(became_available.siblings.is_empty());
        let became_available = phone
            .handle()
            .set_presence(
                Some(0),
                presence("phone").await?,
                Some(unavailable_presence("phone").await?),
            )
            .await?;
        assert!(became_available.became_available);
        assert_eq!(became_available.siblings.len(), 1);
        receive_routed(&desk).await?;

        for _ in 0..64 {
            handle
                .route_full(stanza("alice@localhost/phone").await?)
                .await?;
        }
        let updated = desk
            .handle()
            .set_presence(
                Some(1),
                presence("desk").await?,
                Some(unavailable_presence("desk").await?),
            )
            .await?;
        assert!(!updated.became_available);
        assert!(updated.siblings.is_empty());
        let unavailable = receive_routed(&desk).await?;
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
            receive_routed(&phone).await?;
        }
        assert!(phone.recv().await.is_none());
        assert!(phone.wait_retired().await?.unavailable.is_some());
        assert_eq!(handle.local.withdrawal_snapshot(&alice).await?.len(), 2);
        let unavailable = phone
            .end_presence()
            .await?
            .unavailable
            .ok_or("missing retired presence")?;
        assert_eq!(
            unavailable
                .resolve()?
                .from()?
                .ok_or("missing retired sender")?
                .as_str(),
            "alice@localhost/phone"
        );

        let replacement = handle
            .register(&alice, Some("phone"), NonZeroUsize::new(2).unwrap())
            .await?;
        assert_eq!(replacement.resource(), "phone");
        assert!(!phone.handle().replacement_is_available().await?);
        replacement
            .handle()
            .set_presence(
                Some(0),
                presence("phone").await?,
                Some(unavailable_presence("phone").await?),
            )
            .await?;
        assert!(phone.handle().replacement_is_available().await?);
        assert_eq!(handle.local.withdrawal_snapshot(&alice).await?.len(), 2);
        phone.finish_presence().await?;
        assert_eq!(handle.local.withdrawal_snapshot(&alice).await?.len(), 2);

        drop(desk);
        drop(phone);
        drop(replacement);
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn withdrawal_sees_disconnecting_presence_until_terminal_delivery_finishes() -> TestResult {
    run_test(async {
        let router = setup()?;
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let bob_account = account("bob@localhost")?;
        let alice_desk = handle
            .register(&alice, Some("desk"), NonZeroUsize::MIN)
            .await?;
        let bob = handle
            .register(&bob_account, Some("phone"), NonZeroUsize::MIN)
            .await?;
        alice_desk
            .handle()
            .set_presence(
                Some(0),
                presence("desk").await?,
                Some(unavailable_presence("desk").await?),
            )
            .await?;
        bob.handle().set_presence(
            Some(0),
            parse_stanza("<presence from='bob@localhost/phone' to='bob@localhost'/>").await?,
            Some(
                parse_stanza(
                    "<presence from='bob@localhost/phone' to='bob@localhost' type='unavailable'/>",
                )
                .await?,
            ),
        )
        .await?;

        assert!(alice_desk.end_presence().await?.unavailable.is_some());
        assert!(handle.local.presence_snapshot(&alice).await?.is_empty());
        handle
            .route_unavailable_presence(&alice, &bob_account)
            .await?;
        let unavailable = receive_routed(&bob).await?;
        let view = unavailable.resolve()?;
        assert_eq!(
            view.from()?.ok_or("missing sender")?.as_str(),
            "alice@localhost/desk"
        );
        assert_eq!(
            view.to()?.ok_or("missing target")?.as_str(),
            "bob@localhost"
        );
        alice_desk.finish_presence().await?;
        assert!(handle.local.withdrawal_snapshot(&alice).await?.is_empty());

        drop(alice_desk);
        drop(bob);
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn presence_snapshot_follows_queued_peer_updates() -> TestResult {
    run_test(async {
        let router = setup()?;
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let limit = NonZeroUsize::new(2).ok_or("zero resource limit")?;
        let desk = handle.register(&alice, Some("desk"), limit).await?;
        let phone = handle.register(&alice, Some("phone"), limit).await?;

        assert!(
            desk.handle()
                .set_presence(Some(0), presence("desk").await?, None)
                .await?
                .became_available
        );
        phone
            .handle()
            .set_presence(Some(0), identified_presence("phone", "old").await?, None)
            .await?;
        let away = desk
            .handle()
            .set_presence(None, unavailable_presence("desk").await?, None)
            .await?;
        assert!(away.became_unavailable);
        assert_eq!(away.preceding.len(), 1);
        assert_eq!(away.preceding[0].resolve()?.id()?, Some("old"));
        phone
            .handle()
            .set_presence(Some(0), identified_presence("phone", "new").await?, None)
            .await?;
        let change = desk
            .handle()
            .set_presence(Some(0), presence("desk").await?, None)
            .await?;
        assert!(change.became_available);

        assert!(change.preceding.is_empty());
        assert_eq!(change.siblings.len(), 1);
        assert_eq!(change.siblings[0].resolve()?.id()?, Some("new"));
        assert!(desk.take_queued().is_empty());

        drop(desk);
        drop(phone);
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn full_unavailable_mailbox_retires_recipient() -> TestResult {
    run_test(async {
        let router = setup()?;
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let desk = handle
            .register(&alice, Some("desk"), NonZeroUsize::new(2).unwrap())
            .await?;
        let phone = handle
            .register(&alice, Some("phone"), NonZeroUsize::new(2).unwrap())
            .await?;
        let became_available = desk
            .handle()
            .set_presence(
                Some(0),
                presence("desk").await?,
                Some(unavailable_presence("desk").await?),
            )
            .await?;
        assert!(became_available.became_available);
        let became_available = phone
            .handle()
            .set_presence(Some(0), presence("phone").await?, None)
            .await?;
        assert!(became_available.became_available);
        assert_eq!(became_available.siblings.len(), 1);
        receive_routed(&desk).await?;
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
            receive_routed(&phone).await?;
        }
        assert!(phone.recv().await.is_none());

        drop(phone);
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn a_panic_while_holding_router_state_unwinds_instead_of_aborting() -> TestResult {
    run_test(async {
        let router = setup()?;
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let desk = handle
            .register(&alice, Some("desk"), NonZeroUsize::new(2).unwrap())
            .await?;
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _held = (router, handle, desk);
            panic!("deliberate");
        }));
        assert!(caught.is_err());
        Ok(())
    })
}

#[test]
fn a_panic_while_holding_only_a_registration_unwinds_instead_of_aborting() -> TestResult {
    run_test(async {
        let router = setup()?;
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let desk = handle
            .register(&alice, Some("desk"), NonZeroUsize::new(2).unwrap())
            .await?;
        drop(handle);
        drop(router);
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _held = desk;
            panic!("deliberate");
        }));
        assert!(caught.is_err());
        Ok(())
    })
}

#[test]
fn dropping_an_evicted_registration_clears_its_retained_presence() -> TestResult {
    run_test(async {
        let router = setup()?;
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let desk = handle
            .register(&alice, Some("desk"), NonZeroUsize::new(2).unwrap())
            .await?;
        let phone = handle
            .register(&alice, Some("phone"), NonZeroUsize::new(2).unwrap())
            .await?;
        desk.handle()
            .set_presence(
                Some(0),
                presence("desk").await?,
                Some(unavailable_presence("desk").await?),
            )
            .await?;
        phone
            .handle()
            .set_presence(
                Some(0),
                presence("phone").await?,
                Some(unavailable_presence("phone").await?),
            )
            .await?;
        receive_routed(&desk).await?;
        for _ in 0..64 {
            handle
                .route_full(stanza("alice@localhost/phone").await?)
                .await?;
        }
        desk.handle()
            .set_presence(
                Some(1),
                presence("desk").await?,
                Some(unavailable_presence("desk").await?),
            )
            .await?;
        assert!(phone.wait_retired().await?.unavailable.is_some());
        assert_eq!(handle.local.withdrawal_snapshot(&alice).await?.len(), 2);

        drop(phone);
        for _ in 0..100 {
            if handle.local.withdrawal_snapshot(&alice).await?.len() == 1 {
                break;
            }
            compio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(handle.local.withdrawal_snapshot(&alice).await?.len(), 1);

        drop(desk);
        router.shutdown().await?;
        Ok(())
    })
}

async fn directed_grant(
    source: &Registration<GlobalChunkAllocator>,
    to: &str,
    available: bool,
) -> Result<(), Box<dyn Error>> {
    let kind = if available { "" } else { " type='unavailable'" };
    source
        .handle()
        .directed_presence(
            parse_stanza(&format!(
                "<presence from='{}' to='{to}'{kind}/>",
                source.full_jid()
            ))
            .await?,
            available,
        )
        .await?;
    Ok(())
}

async fn has_grant(
    handle: &super::RouterHandle<GlobalChunkAllocator>,
    source: &AccountKey,
    resource: &str,
    observer: &str,
) -> Result<bool, Box<dyn Error>> {
    let mut arena = Arena::try_new(Default::default())?;
    let observer = Jid::parse_in(observer, &mut arena)?.resolve(&arena)?;
    Ok(handle
        .has_directed_grant(source, resource, observer)
        .await?)
}

#[test]
fn directed_grants_keep_exact_recipients_and_source_resources() -> TestResult {
    run_test(async {
        let router = setup()?;
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let limit = NonZeroUsize::new(2).ok_or("zero limit")?;
        let desk = handle.register(&alice, Some("desk"), limit).await?;
        let phone = handle.register(&alice, Some("phone"), limit).await?;
        directed_grant(&desk, "bob@localhost/desk", true).await?;
        assert!(has_grant(&handle, &alice, "desk", "bob@localhost/desk").await?);
        assert!(!has_grant(&handle, &alice, "desk", "bob@localhost/phone").await?);
        assert!(!has_grant(&handle, &alice, "desk", "bob@localhost").await?);
        assert!(!has_grant(&handle, &alice, "phone", "bob@localhost/desk").await?);
        directed_grant(&desk, "bob@localhost", true).await?;
        assert!(has_grant(&handle, &alice, "desk", "bob@localhost/phone").await?);
        directed_grant(&desk, "bob@localhost/desk", false).await?;
        assert!(has_grant(&handle, &alice, "desk", "bob@localhost/desk").await?);
        directed_grant(&desk, "bob@localhost", false).await?;
        assert!(!has_grant(&handle, &alice, "desk", "bob@localhost/desk").await?);
        drop((desk, phone));
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn incoming_unavailable_prunes_connected_only_grants_by_sender_scope() -> TestResult {
    run_test(async {
        let router = setup()?;
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let limit = NonZeroUsize::new(2).ok_or("zero limit")?;
        let desk = handle.register(&alice, Some("desk"), limit).await?;
        let phone = handle.register(&alice, Some("phone"), limit).await?;
        for source in [&desk, &phone] {
            for target in ["bob@localhost", "bob@localhost/desk", "bob@localhost/phone"] {
                directed_grant(source, target, true).await?;
            }
        }
        handle.route_directed_presence(parse_stanza("<presence from='bob@localhost/desk' to='alice@localhost/desk' type='unavailable'/>").await?).await?;
        assert!(has_grant(&handle, &alice, "desk", "bob@localhost/desk").await?);
        directed_grant(&desk, "bob@localhost", false).await?;
        assert!(!has_grant(&handle, &alice, "desk", "bob@localhost/desk").await?);
        assert!(has_grant(&handle, &alice, "desk", "bob@localhost/phone").await?);
        assert!(has_grant(&handle, &alice, "phone", "bob@localhost/desk").await?);
        handle
            .route_directed_presence(
                parse_stanza(
                    "<presence from='bob@localhost' to='alice@localhost' type='unavailable'/>",
                )
                .await?,
            )
            .await?;
        for resource in ["desk", "phone"] {
            for observer in ["bob@localhost", "bob@localhost/desk", "bob@localhost/phone"] {
                assert!(!has_grant(&handle, &alice, resource, observer).await?);
            }
        }
        drop((desk, phone));
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn retirement_transfers_grants_once_and_stale_handles_cannot_change_replacement() -> TestResult {
    run_test(async {
        let router = setup()?;
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let desk = handle
            .register(&alice, Some("desk"), NonZeroUsize::MIN)
            .await?;
        let old = desk.handle();
        directed_grant(&desk, "bob@localhost/desk", true).await?;
        handle.retire_account(&alice).await?;
        let first = desk.wait_retired().await?;
        let second = first.clone();
        assert_eq!(first.cause, second.cause);
        let owned = old.end_presence().await?;
        assert_eq!(owned.directed.recipients.len(), 1);
        assert!(old.end_presence().await?.directed.recipients.is_empty());
        let replacement = handle
            .register(&alice, Some("desk"), NonZeroUsize::MIN)
            .await?;
        directed_grant(&replacement, "carol@localhost/desk", true).await?;
        assert_eq!(old.directed_presence(parse_stanza("<presence from='alice@localhost/desk' to='carol@localhost/desk' type='unavailable'/>").await?, false).await, Err(RouterError::NotFound));
        old.finish_presence(owned.directed.source_token).await?;
        assert!(has_grant(&handle, &alice, "desk", "carol@localhost/desk").await?);
        drop((desk, replacement));
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn guarded_presence_is_dropped_once_its_source_retires() -> TestResult {
    run_test(async {
        let router = setup()?;
        let handle = router.handle();
        let desk = handle
            .register(
                &account("alice@localhost")?,
                Some("desk"),
                NonZeroUsize::MIN,
            )
            .await?;
        let bob = handle
            .register(&account("bob@localhost")?, Some("phone"), NonZeroUsize::MIN)
            .await?;
        bob.handle()
            .set_presence(
                Some(0),
                parse_stanza("<presence from='bob@localhost/phone'/>").await?,
                None,
            )
            .await?;
        bob.take_queued();
        let liveness = desk.liveness();
        handle
            .local
            .deliver_presence_guarded(
                parse_stanza("<presence from='alice@localhost/desk' to='bob@localhost'/>").await?,
                liveness.clone(),
            )
            .await?;
        assert_eq!(bob.take_queued().len(), 1);
        handle
            .local
            .deliver_full_guarded(
                parse_stanza("<presence from='alice@localhost/desk' to='bob@localhost/phone'/>")
                    .await?,
                liveness.clone(),
            )
            .await?;
        assert_eq!(bob.take_queued().len(), 1);

        drop(desk);
        assert!(!liveness.is_alive());
        assert_eq!(
            handle
                .local
                .deliver_presence_guarded(
                    parse_stanza("<presence from='alice@localhost/desk' to='bob@localhost'/>")
                        .await?,
                    liveness.clone(),
                )
                .await,
            Err(RouterError::NotFound)
        );
        assert!(bob.take_queued().is_empty());
        handle
            .local
            .deliver_full_guarded(
                parse_stanza("<presence from='alice@localhost/desk' to='bob@localhost/phone'/>")
                    .await?,
                liveness,
            )
            .await?;
        assert!(bob.take_queued().is_empty());
        drop(bob);
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn unavailable_probe_reply_prunes_the_requester_grant() -> TestResult {
    run_test(async {
        let router = setup()?;
        let handle = router.handle();
        let bob_account = account("bob@localhost")?;
        let bob = handle
            .register(&bob_account, Some("desk"), NonZeroUsize::MIN)
            .await?;
        directed_grant(&bob, "alice@localhost", true).await?;
        assert!(has_grant(&handle, &bob_account, "desk", "alice@localhost").await?);
        let probe =
            parse_stanza("<presence from='bob@localhost/desk' to='alice@localhost' type='probe'/>")
                .await?;
        handle.probe_presence(&bob.handle(), &probe, true).await?;
        let replies = bob.take_queued();
        assert_eq!(replies.len(), 1);
        assert_eq!(
            replies[0].resolve()?.stanza_type(),
            StanzaType::Presence(super::PresenceType::Unavailable)
        );
        assert!(!has_grant(&handle, &bob_account, "desk", "alice@localhost").await?);
        directed_grant(&bob, "alice@localhost", true).await?;
        let queued = parse_stanza(
            "<presence from='carol@localhost/desk' to='bob@localhost/desk' id='queued'/>",
        )
        .await?;
        let mut count = 0;
        loop {
            match handle.route_full(queued.clone()).await {
                Ok(()) => count += 1,
                Err(RouterError::Busy) => break,
                Err(error) => return Err(error.into()),
            }
        }
        assert!(count > 0);
        assert!(has_grant(&handle, &bob_account, "desk", "alice@localhost").await?);
        handle.probe_presence(&bob.handle(), &probe, true).await?;
        assert!(!has_grant(&handle, &bob_account, "desk", "alice@localhost").await?);
        assert!(bob.liveness().is_alive());
        let replies = bob.take_queued();
        assert_eq!(replies.len(), count);
        for reply in replies {
            assert_eq!(reply.resolve()?.id()?, Some("queued"));
        }
        drop(bob);
        router.shutdown().await?;
        Ok(())
    })
}

async fn iq_request(
    from: &str,
    to: &str,
) -> Result<RoutedStanza<GlobalChunkAllocator>, Box<dyn Error>> {
    parse_stanza(&format!(
        "<iq type='get' from='{from}' to='{to}' id='request'><query xmlns='urn:test:iq'/></iq>"
    ))
    .await
}

#[test]
fn iq_requests_authorize_exact_resource_grants_and_same_accounts() -> TestResult {
    run_test(async {
        let router = setup()?;
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let desk = handle
            .register(&alice, Some("desk"), NonZeroUsize::MIN.saturating_add(1))
            .await?;
        let phone = handle
            .register(&alice, Some("phone"), NonZeroUsize::MIN.saturating_add(1))
            .await?;
        let target = "alice@localhost/desk";
        handle
            .route_iq_request(iq_request("alice@localhost/phone", target).await?, false)
            .await?;
        assert_eq!(desk.take_queued().len(), 1);
        assert_eq!(
            handle
                .route_iq_request(iq_request("bob@localhost/desk", target).await?, false)
                .await,
            Err(RouterError::NotFound)
        );
        directed_grant(&phone, "bob@localhost/desk", true).await?;
        assert_eq!(
            handle
                .route_iq_request(iq_request("bob@localhost/desk", target).await?, false)
                .await,
            Err(RouterError::NotFound)
        );
        directed_grant(&desk, "bob@localhost/desk", true).await?;
        handle
            .route_iq_request(iq_request("bob@localhost/desk", target).await?, false)
            .await?;
        assert_eq!(desk.take_queued().len(), 1);
        assert_eq!(
            handle
                .route_iq_request(iq_request("bob@localhost/phone", target).await?, false)
                .await,
            Err(RouterError::NotFound)
        );
        directed_grant(&desk, "bob@localhost/desk", false).await?;
        assert_eq!(
            handle
                .route_iq_request(iq_request("bob@localhost/desk", target).await?, false)
                .await,
            Err(RouterError::NotFound)
        );
        directed_grant(&desk, "bob@localhost", true).await?;
        handle
            .route_iq_request(iq_request("bob@localhost/phone", target).await?, false)
            .await?;
        assert_eq!(desk.take_queued().len(), 1);
        directed_grant(&desk, "bob@localhost", false).await?;
        for priority in [None, Some(-1)] {
            desk.handle()
                .set_presence(
                    priority,
                    presence("desk").await?,
                    Some(unavailable_presence("desk").await?),
                )
                .await?;
            handle
                .route_iq_request(iq_request("bob@localhost/phone", target).await?, true)
                .await?;
            assert_eq!(desk.take_queued().len(), 1);
        }
        drop((desk, phone));
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn iq_requests_do_not_fall_back_on_backpressure_or_reuse_replaced_grants() -> TestResult {
    run_test(async {
        let router = setup()?;
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        let desk = handle
            .register(&alice, Some("desk"), NonZeroUsize::MIN.saturating_add(1))
            .await?;
        let phone = handle
            .register(&alice, Some("phone"), NonZeroUsize::MIN.saturating_add(1))
            .await?;
        directed_grant(&desk, "bob@localhost/desk", true).await?;
        let request = iq_request("bob@localhost/desk", "alice@localhost/desk").await?;
        for _ in 0..64 {
            handle.route_iq_request(request.clone(), false).await?;
        }
        assert_eq!(
            handle.route_iq_request(request.clone(), false).await,
            Err(RouterError::Busy)
        );
        assert!(phone.take_queued().is_empty());
        assert_eq!(desk.take_queued().len(), 64);
        drop(desk);
        let replacement = handle
            .register(&alice, Some("desk"), NonZeroUsize::MIN.saturating_add(1))
            .await?;
        assert_eq!(
            handle.route_iq_request(request.clone(), false).await,
            Err(RouterError::NotFound)
        );
        assert!(replacement.take_queued().is_empty());
        directed_grant(&replacement, "bob@localhost/desk", true).await?;
        handle.route_iq_request(request.clone(), false).await?;
        assert_eq!(replacement.take_queued().len(), 1);
        handle.retire_account(&alice).await?;
        assert_eq!(
            handle.route_iq_request(request, true).await,
            Err(RouterError::NotFound)
        );
        drop((phone, replacement));
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn resource_match_observes_connected_tokens_without_availability_or_capacity_filters() -> TestResult
{
    run_test(async {
        let router = setup()?;
        let handle = router.handle();
        let alice = account("alice@localhost")?;
        assert_eq!(handle.resource_match(&alice, "desk").await?, None);
        assert_eq!(
            handle
                .resource_match(&account("alice@example.com")?, "desk")
                .await,
            Err(RouterError::RemoteUnsupported)
        );
        let desk = handle
            .register(&alice, Some("desk"), NonZeroUsize::MIN)
            .await?;
        let observed = handle
            .resource_match(&alice, "desk")
            .await?
            .ok_or("missing resource")?;
        assert_eq!(handle.resource_match(&alice, "Desk").await?, None);
        for _ in 0..64 {
            handle
                .route_full(stanza("alice@localhost/desk").await?)
                .await?;
        }
        assert_eq!(handle.resource_match(&alice, "desk").await?, Some(observed));
        assert!(desk.liveness().is_alive());
        desk.take_queued();
        let before = handle
            .resource_match(&alice, "desk")
            .await?
            .ok_or("missing resource")?;
        handle.retire_account(&alice).await?;
        assert_eq!(handle.resource_match(&alice, "desk").await?, None);
        let replacement = handle
            .register(&alice, Some("desk"), NonZeroUsize::MIN)
            .await?;
        let after = handle
            .resource_match(&alice, "desk")
            .await?
            .ok_or("missing replacement")?;
        assert_ne!(before.token, after.token);
        drop(desk);
        assert_eq!(handle.resource_match(&alice, "desk").await?, Some(after));
        drop(replacement);
        assert_eq!(handle.resource_match(&alice, "desk").await?, None);
        router.shutdown().await?;
        assert_eq!(
            handle.resource_match(&alice, "desk").await,
            Err(RouterError::Stopped)
        );
        Ok(())
    })
}
