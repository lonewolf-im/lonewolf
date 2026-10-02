// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::error::Error;
use std::num::NonZeroUsize;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
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
use lonewolf_util::core_dispatcher::CoreDispatcher;
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::{ParserConfig, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::{RoutedStanza, StanzaErrorCondition};

use super::{StoredDelivery, commit_and_deliver, commit_and_store};
use crate::config::Config;
use crate::hosts::Hosts;
use crate::order::Order;
use crate::router::local::LocalRouter;
use crate::router::{Router, RouterError};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

mod logging;

struct AckNotice {
    done: Mutex<Option<oneshot::Sender<()>>>,
    release: Mutex<Option<oneshot::Receiver<()>>>,
}

impl MessageHandler<GlobalChunkAllocator, RedbStorage> for AckNotice {
    fn acknowledge_one<'a>(
        &'a self,
        account: &'a AccountKey,
        sequence: OfflineSequence,
        transaction: &'a mut RedbWrite,
    ) -> ExtensionFuture<'a, Result<(), HandlerError>> {
        Box::pin(async move {
            if let Some(done) = self
                .done
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
            {
                let _ = done.send(());
            }
            let release = self
                .release
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
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
        let dispatcher = CoreDispatcher::new(NonZeroUsize::MIN, NonZeroUsize::MIN)?;
        let config = Config::default();
        let hosts = Hosts::new(&config.hosts, None)?;
        let local = LocalRouter::start(&dispatcher.handle(), GlobalChunkAllocator).await?;
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
            done: Mutex::new(Some(done)),
            release: Mutex::new(None),
        });
        let pending = commit_and_store(
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
        dispatcher.shutdown(Duration::from_secs(5)).await?;
        Ok(())
    }))?
}

#[test]
fn committed_deletion_keeps_retirement_and_recreation_behind_live_acknowledgement() -> TestResult {
    let capture = crate::logging::tests::Capture::new()?;
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
        let dispatcher = CoreDispatcher::new(NonZeroUsize::MIN, NonZeroUsize::MIN)?;
        let config = Config::default();
        let local = LocalRouter::start(&dispatcher.handle(), GlobalChunkAllocator).await?;
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
            handle.clone(),
            storage.clone(),
            transaction,
            Arc::new(AckNotice {
                done: Mutex::new(Some(done)),
                release: Mutex::new(Some(released)),
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
        assert_eq!(
            capture.count("operation=\"reroute\" outcome=\"queued\"")?,
            1
        );
        assert_eq!(
            capture.count("operation=\"acknowledge_live\" outcome=\"committed\"")?,
            0
        );
        assert!(retirement.turn().now_or_never().is_none());
        release
            .send(())
            .map_err(|_| "acknowledgement gate closed")?;
        assert!(matches!(pending.finished().await, Some(Ok(()))));
        assert_eq!(
            capture.count("operation=\"acknowledge_live\" outcome=\"committed\"")?,
            1
        );
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
        dispatcher.shutdown(Duration::from_secs(5)).await?;
        Ok(())
    }))?
}

struct NoDelivery;

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

fn account(value: &str) -> TestResult<AccountKey> {
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
        let effects = Effects::new(vec![alice], move |_| {
            Box::pin(async move {
                flag.set(true);
                Ok(())
            })
        });
        let committed = commit_and_deliver(
            Arc::clone(&order),
            storage.begin_write().await?,
            effects,
            NoDelivery,
            None,
        );
        drop(committed);
        compio::time::sleep(Duration::from_millis(20)).await;
        assert!(!ran.get(), "effects ran before their turn");

        drop(ahead);
        for _ in 0..50 {
            if ran.get() {
                break;
            }
            compio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(ran.get(), "effects were lost with their caller");
        Ok(())
    })
}
