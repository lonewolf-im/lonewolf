// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::error::Error;
use std::num::NonZeroUsize;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use compio::runtime::Runtime;
use futures_channel::oneshot;
use futures_util::FutureExt;
use lonewolf_auth::scram::{
    SCRAM_POLICY_ITERATIONS, ScramCredentials, ScramSha1Verifier, ScramVerifier,
};
use lonewolf_extension::Effects;
use lonewolf_extension::ExtensionFuture;
use lonewolf_extension::delivery::{
    Delivery, DeliveryError, DeliveryFuture, HandlerError, HostLookup, SessionTag, StanzaFactory,
};
use lonewolf_extension::message::MessageHandler;
use lonewolf_storage::account::{AccountKey, AccountWrites, NewAccount};
use lonewolf_storage::offline::{OfflineReads, OfflineSequence, OfflineWrites};
use lonewolf_storage::{RedbStorage, RedbWrite, Storage, WriteTransaction};
use lonewolf_util::arena::{Arena, ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::{ParserConfig, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::{RoutedStanza, StanzaErrorCondition};
use parking_lot::Mutex as PlMutex;

use super::{EffectsDiagnostics, StoredDelivery, WorkGroup, commit_and_deliver, commit_and_store};
use crate::config::Config;
use crate::hosts::Hosts;
use crate::order::Order;
use crate::router::local::LocalRouter;
use crate::router::{Router, RouterError};

pub(super) type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct AckNotice {
    done: PlMutex<Option<oneshot::Sender<()>>>,
    release: PlMutex<Option<oneshot::Receiver<()>>>,
}

impl MessageHandler<GlobalChunkAllocator, RedbStorage> for AckNotice {
    fn acknowledge_one<'a>(
        &'a self,
        account: &'a AccountKey,
        sequence: OfflineSequence,
        transaction: &'a mut RedbWrite,
    ) -> ExtensionFuture<'a, Result<(), HandlerError>> {
        Box::pin(async move {
            if let Some(done) = self.done.lock().take() {
                let _ = done.send(());
            }
            let release = self.release.lock().take();
            if let Some(release) = release {
                release
                    .await
                    .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            }
            transaction
                .remove_offline_message(account, sequence)
                .await
                .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            Ok(())
        })
    }
}

async fn parsed(xml: &str) -> TestResult<RoutedStanza<GlobalChunkAllocator>> {
    let input = format!(
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'>{xml}"
    );
    let mut parser = XmppParser::new(
        input.as_bytes(),
        ParserConfig {
            max_stanza_bytes: NonZeroUsize::new(4096).ok_or("invalid stanza limit")?,
            arena: ArenaConfig::default(),
        },
        GlobalChunkAllocator,
    );
    assert!(matches!(
        parser.next_event().await?,
        Some(StreamEvent::StreamStart { .. })
    ));
    match parser.next_event().await? {
        Some(StreamEvent::Stanza(stanza)) => Ok(RoutedStanza::from_parsed(stanza)),
        _ => Err("expected stanza".into()),
    }
}

#[test]
fn stored_message_commits_and_reroutes_after_its_requester_drops_before_the_ticket_turns()
-> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
        let config = Config::default();
        let hosts = Hosts::new(&config.hosts, None)?;
        let local = LocalRouter::new(GlobalChunkAllocator);
        let router = Router::new(hosts, local);
        let handle = router.handle();
        let owner = account("bob@localhost")?;
        let mut transaction = storage.begin_write().await?;
        transaction
            .create_account(NewAccount {
                key: owner.clone(),
                credentials: ScramCredentials::new(ScramVerifier::Sha1(ScramSha1Verifier::new(
                    [11; 16],
                    SCRAM_POLICY_ITERATIONS,
                    [12; 20],
                    [13; 20],
                ))),
            })
            .await?;
        transaction.commit().await?;
        let registration = handle
            .register(&owner, Some("phone"), NonZeroUsize::MIN)
            .await?;
        let stanza = parsed("<message to='bob@localhost' type='chat' id='raced'/>").await?;
        assert_eq!(
            handle.route_message(stanza.clone()).await,
            Err(RouterError::Offline)
        );
        let ((), ahead) = handle
            .order()
            .fix(vec![owner.clone()], async { Ok::<_, DeliveryError>(()) })
            .await?;
        let mut transaction = storage.begin_write().await?;
        let sequence = transaction
            .push_offline_message(&owner, 0, b"<message to='bob@localhost'/>")
            .await?;
        let (done, acknowledged) = oneshot::channel();
        let handler = Arc::new(AckNotice {
            done: PlMutex::new(Some(done)),
            release: PlMutex::new(None),
        });
        let pending = commit_and_store(
            WorkGroup::new().start(),
            handle.clone(),
            storage.clone(),
            transaction,
            handler,
            StoredDelivery {
                recipient: owner.clone(),
                sequence,
                stanza,
                bytes: 0,
            },
        );
        drop(pending);
        let committed = storage.begin_write().await?;
        assert_eq!(committed.offline_count(&owner).await?, 1);
        drop(committed);
        assert!(registration.take_queued().is_empty());
        registration
            .handle()
            .set_presence(
                Some(0),
                parsed("<presence from='bob@localhost/phone'/>").await?,
                Some(parsed("<presence from='bob@localhost/phone' type='unavailable'/>").await?),
            )
            .await?;
        drop(ahead);
        let delivered = registration.recv().await.ok_or("missing live reroute")?;
        assert_eq!(delivered.resolve()?.id()?, Some("raced"));
        acknowledged.await?;
        let committed = storage.begin_write().await?;
        assert_eq!(committed.offline_count(&owner).await?, 0);
        drop(committed);
        drop(registration);
        router.shutdown().await?;
        Ok(())
    }))?
}

#[test]
fn committed_deletion_keeps_retirement_and_recreation_behind_live_acknowledgement() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
        let config = Config::default();
        let local = LocalRouter::new(GlobalChunkAllocator);
        let router = Router::new(Hosts::new(&config.hosts, None)?, local);
        let handle = router.handle();
        let owner = account("bob@localhost")?;
        let credentials = ScramCredentials::new(ScramVerifier::Sha1(ScramSha1Verifier::new(
            [11; 16],
            SCRAM_POLICY_ITERATIONS,
            [12; 20],
            [13; 20],
        )));
        let mut transaction = storage.begin_write().await?;
        transaction
            .create_account(NewAccount {
                key: owner.clone(),
                credentials: credentials.clone(),
            })
            .await?;
        transaction.commit().await?;
        let registration = handle
            .register(&owner, Some("phone"), NonZeroUsize::MIN)
            .await?;
        let ((), ahead) = handle
            .order()
            .fix(vec![owner.clone()], async { Ok::<_, DeliveryError>(()) })
            .await?;
        let mut transaction = storage.begin_write().await?;
        let sequence = transaction
            .push_offline_message(&owner, 0, b"<message to='bob@localhost'/>")
            .await?;
        let (done, acknowledging) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let pending = commit_and_store(
            WorkGroup::new().start(),
            handle.clone(),
            storage.clone(),
            transaction,
            Arc::new(AckNotice {
                done: PlMutex::new(Some(done)),
                release: PlMutex::new(Some(released)),
            }),
            StoredDelivery {
                recipient: owner.clone(),
                sequence,
                stanza: parsed("<message to='bob@localhost' type='chat' id='raced'/>").await?,
                bytes: 0,
            },
        );
        let mut deletion = storage.begin_write().await?;
        deletion.delete_account(&owner).await?;
        deletion.clear_offline_messages(&owner).await?;
        registration
            .handle()
            .set_presence(
                Some(0),
                parsed("<presence from='bob@localhost/phone'/>").await?,
                Some(parsed("<presence from='bob@localhost/phone' type='unavailable'/>").await?),
            )
            .await?;
        drop(ahead);
        let delivered = registration.recv().await.ok_or("missing live reroute")?;
        assert_eq!(delivered.resolve()?.id()?, Some("raced"));
        let ((), mut retirement) = handle
            .order()
            .fix(vec![owner.clone()], deletion.commit())
            .await?;
        acknowledging.await?;
        assert!(retirement.turn().now_or_never().is_none());
        release
            .send(())
            .map_err(|_| "acknowledgement gate closed")?;
        assert!(matches!(pending.finished().await, Some(Ok(()))));
        retirement.turn().await;
        handle.retire_account(&owner).await?;
        drop(retirement);
        let mut recreation = storage.begin_write().await?;
        recreation
            .create_account(NewAccount {
                key: owner.clone(),
                credentials,
            })
            .await?;
        let fresh = recreation
            .push_offline_message(&owner, 1, b"<message to='bob@localhost' id='fresh'/>")
            .await?;
        assert_eq!(fresh.get(), 1);
        recreation.commit().await?;
        let snapshot = storage.begin_read().await?;
        assert_eq!(snapshot.offline_count(&owner).await?, 1);
        drop(snapshot);
        drop(registration);
        router.shutdown().await?;
        Ok(())
    }))?
}

pub(super) struct NoDelivery;

impl HostLookup for NoDelivery {
    fn is_local_host(&self, _: &str) -> bool {
        true
    }
}

impl Delivery<GlobalChunkAllocator> for NoDelivery {
    fn arena(&self) -> Result<Arena<GlobalChunkAllocator>, DeliveryError> {
        Arena::try_new(ArenaConfig::default()).map_err(|_| DeliveryError)
    }

    fn tag_session<'a>(&'a self, _: SessionTag) -> DeliveryFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn to_available<'a>(&'a self, _: RoutedStanza<GlobalChunkAllocator>) -> DeliveryFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn to_tagged<'a>(
        &'a self,
        _: SessionTag,
        _: RoutedStanza<GlobalChunkAllocator>,
    ) -> DeliveryFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn push_to_tagged<'a>(
        &'a self,
        _: &'a AccountKey,
        _: SessionTag,
        _: StanzaFactory<GlobalChunkAllocator>,
    ) -> DeliveryFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn current_presence<'a>(&'a self, _: &'a AccountKey, _: &'a AccountKey) -> DeliveryFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn unavailable_presence<'a>(
        &'a self,
        _: &'a AccountKey,
        _: &'a AccountKey,
    ) -> DeliveryFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

pub(super) fn account(value: &str) -> TestResult<AccountKey> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let jid = Jid::parse_in(value, &mut arena)?;
    Ok(AccountKey::try_from(jid.resolve(&arena)?)?)
}

#[test]
fn a_change_committed_after_its_caller_is_gone_still_delivers_in_order() -> TestResult {
    Runtime::new()?.block_on(async {
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
        let order = Order::new();
        let alice = account("alice@example.com")?;
        let ((), ahead) = order
            .fix(vec![alice.clone()], async { Ok::<_, DeliveryError>(()) })
            .await?;
        let ran = Rc::new(Cell::new(false));
        let flag = Rc::clone(&ran);
        let effects = Effects::new(vec![alice.clone()], move |_| {
            Box::pin(async move {
                flag.set(true);
                Ok(())
            })
        });
        let mut work = WorkGroup::new();
        let committed = commit_and_deliver(
            work.start(),
            Arc::clone(&order),
            storage.begin_write().await?,
            effects,
            NoDelivery,
            None,
            EffectsDiagnostics {
                account: alice,
                commit_operation: "iq_set_commit",
                delivery_operation: "iq_set_effects",
            },
        );
        drop(committed);
        compio::time::sleep(Duration::from_millis(20)).await;
        assert!(!ran.get(), "effects ran before their turn");
        assert!(work.drain().now_or_never().is_none());

        drop(ahead);
        compio::time::timeout(Duration::from_secs(1), work.drain()).await?;
        assert!(ran.get(), "effects were lost with their caller");
        Ok(())
    })
}

#[test]
fn work_admitted_before_spawn_is_drained_after_cancellation() {
    let mut group = WorkGroup::new();
    let work = group.start().run(std::future::pending::<()>());
    assert!(group.drain().now_or_never().is_none());
    drop(work);
    assert!(group.drain().now_or_never().is_some());

    let mut work = Box::pin(group.start().run(std::future::pending::<()>()));
    assert!(work.as_mut().now_or_never().is_none());
    assert!(group.drain().now_or_never().is_none());
    drop(work);
    assert!(group.drain().now_or_never().is_some());
}

#[test]
fn panicked_work_wakes_its_drain_and_preserves_the_panic() {
    use futures_util::task::{ArcWake, waker};
    use std::panic::AssertUnwindSafe;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};

    struct WakeCount(AtomicUsize);
    impl ArcWake for WakeCount {
        fn wake_by_ref(value: &Arc<Self>) {
            value.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    let mut group = WorkGroup::new();
    let work = group.start().run(async { std::panic::panic_any(42_u32) });
    let count = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = waker(Arc::clone(&count));
    let mut context = Context::from_waker(&waker);
    let mut drain = Box::pin(group.drain());
    assert!(matches!(
        std::future::Future::poll(drain.as_mut(), &mut context),
        Poll::Pending
    ));
    let result = AssertUnwindSafe(work).catch_unwind().now_or_never();
    let Some(Err(payload)) = result else {
        panic!("work did not retain its panic")
    };
    assert_eq!(payload.downcast_ref::<u32>(), Some(&42));
    assert_eq!(count.0.load(Ordering::Relaxed), 1);
    assert!(matches!(
        std::future::Future::poll(drain.as_mut(), &mut context),
        Poll::Ready(())
    ));
}
