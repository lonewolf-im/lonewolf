// SPDX-License-Identifier: Apache-2.0

use std::alloc::Layout;
use std::error::Error;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use compio::runtime::Runtime;
use futures_channel::oneshot;
use futures_util::poll;
use lonewolf_auth::scram::{
    SCRAM_POLICY_ITERATIONS, ScramCredentials, ScramSha1Verifier, ScramVerifier,
};
use lonewolf_extension::message::MessageHandler;
use lonewolf_extension::offline::Offline;
use lonewolf_storage::account::{AccountWrites, NewAccount};
use lonewolf_storage::offline::{OfflineReads, OfflineWrites};
use lonewolf_util::arena::{AllocationError, Chunk, GlobalChunkAllocator};
use lonewolf_util::core_dispatcher::CoreDispatcher;
use lonewolf_util::pool::{PoolConfig, PooledChunkAllocator};

use super::*;
use crate::config::Config;
use crate::hosts::Hosts;
use crate::router::Router;
use crate::router::local::LocalRouter;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const MESSAGE: &[u8] =
    b"<message xmlns='jabber:client' to='bob@localhost/old' type='chat' id='stored'/>";

mod logging;

#[derive(Default)]
struct ControlledWriter {
    written: Vec<String>,
    fail_write: bool,
    fail_flush: bool,
    flush_entered: Option<oneshot::Sender<()>>,
    flush_release: Option<oneshot::Receiver<()>>,
    pool: Option<Arc<PooledChunkAllocator>>,
    maximum_chunks: usize,
    fail_allocation_after_write: Option<Arc<AtomicBool>>,
}

impl OutboxWriter for ControlledWriter {
    async fn write_stanza<R: ArenaRead>(
        &mut self,
        stanza: &StanzaRef<'_, R>,
    ) -> Result<(), CloseOutcome> {
        if self.fail_write {
            return Err(CloseOutcome::TransportError);
        }
        if let Some(pool) = &self.pool {
            let live = pool
                .stats()
                .buckets
                .iter()
                .map(|bucket| bucket.total_chunks - bucket.available_chunks)
                .sum();
            self.maximum_chunks = self.maximum_chunks.max(live);
        }
        let mut xml = String::new();
        stanza
            .write_xml(&mut xml)
            .map_err(|_| CloseOutcome::InternalError)?;
        self.written.push(xml);
        if let Some(failure) = &self.fail_allocation_after_write {
            failure.store(true, Ordering::Release);
        }
        Ok(())
    }

    async fn flush(&mut self) -> Result<(), CloseOutcome> {
        if let Some(entered) = self.flush_entered.take() {
            let _ = entered.send(());
        }
        if let Some(release) = self.flush_release.take() {
            release.await.map_err(|_| CloseOutcome::TransportError)?;
        }
        if self.fail_flush {
            Err(CloseOutcome::TransportError)
        } else {
            Ok(())
        }
    }
}

struct AckNotice(Mutex<Option<oneshot::Sender<()>>>);

impl<A: ChunkAllocator> MessageHandler<A, RedbStorage> for AckNotice {
    fn acknowledge<'a>(
        &'a self,
        account: &'a AccountKey,
        through: lonewolf_storage::offline::OfflineSequence,
        transaction: &'a mut lonewolf_storage::RedbWrite,
    ) -> lonewolf_extension::ExtensionFuture<'a, Result<(), HandlerError>> {
        Box::pin(async move {
            <Offline as MessageHandler<A, RedbStorage>>::acknowledge(
                &Offline::new(Default::default()),
                account,
                through,
                transaction,
            )
            .await?;
            if let Some(done) = self
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
            {
                let _ = done.send(());
            }
            Ok(())
        })
    }
}

async fn flush_and_ack<A: ChunkAllocator + Clone>(
    fixture: &Fixture,
    outbox: &mut Outbox<A, ControlledWriter>,
) -> TestResult {
    let (done, acknowledged) = oneshot::channel();
    outbox.push(Output::Offline {
        backlog: fixture.backlog().await?,
        handler: Arc::new(AckNotice(Mutex::new(Some(done)))),
    });
    outbox.flush().await.map_err(|error| format!("{error:?}"))?;
    acknowledged.await?;
    drop(fixture.storage.begin_write().await?);
    Ok(())
}

struct Fixture {
    _directory: tempfile::TempDir,
    storage: RedbStorage,
    router: Router<GlobalChunkAllocator>,
    dispatcher: CoreDispatcher,
    registration: Registration<GlobalChunkAllocator>,
}

fn credentials() -> ScramCredentials {
    ScramCredentials::new(ScramVerifier::Sha1(ScramSha1Verifier::new(
        [1; 16],
        SCRAM_POLICY_ITERATIONS,
        [2; 20],
        [3; 20],
    )))
}

impl Fixture {
    async fn new(messages: &[&[u8]]) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
        let dispatcher = CoreDispatcher::new(NonZeroUsize::MIN, NonZeroUsize::MIN)?;
        let config = Config::default();
        let local = LocalRouter::start(&dispatcher.handle(), GlobalChunkAllocator).await?;
        let router = Router::new(Hosts::new(&config.hosts, None)?, local);
        let mut arena = Arena::try_new(ArenaConfig::default())?;
        let account =
            AccountKey::try_from(Jid::parse_in("bob@localhost", &mut arena)?.resolve(&arena)?)?;
        let mut transaction = storage.begin_write().await?;
        transaction
            .create_account(NewAccount {
                key: account.clone(),
                credentials: credentials(),
            })
            .await?;
        for message in messages {
            transaction
                .push_offline_message(&account, 0, message)
                .await?;
        }
        transaction.commit().await?;
        let registration = router
            .handle()
            .register(&account, Some("phone"), NonZeroUsize::MIN)
            .await?;
        Ok(Self {
            _directory: directory,
            storage,
            router,
            dispatcher,
            registration,
        })
    }

    fn outbox<A: ChunkAllocator>(
        &self,
        allocator: A,
        writer: ControlledWriter,
    ) -> Outbox<A, ControlledWriter> {
        Outbox {
            queue: VecDeque::new(),
            writer,
            allocator,
            account: self.registration.account().clone(),
            storage: self.storage.clone(),
            liveness: self.registration.liveness(),
            acknowledgement: None,
        }
    }

    async fn backlog(&self) -> TestResult<Backlog> {
        let snapshot = self.storage.begin_read().await?;
        let messages = snapshot
            .offline_messages(self.registration.account())
            .await?;
        let through = messages.last().ok_or("missing backlog")?.sequence;
        Ok(Backlog { messages, through })
    }

    async fn count(&self) -> TestResult<usize> {
        Ok(self
            .storage
            .begin_read()
            .await?
            .offline_count(self.registration.account())
            .await?)
    }

    async fn finish(self) -> TestResult {
        drop(self.registration);
        self.router.shutdown().await?;
        self.dispatcher.shutdown(Duration::from_secs(5)).await?;
        Ok(())
    }
}

#[test]
fn failed_write_or_flush_keeps_backlog_for_a_successful_retry() -> TestResult {
    Runtime::new()?.block_on(async {
        for fail_write in [false, true] {
            let fixture = Fixture::new(&[MESSAGE, MESSAGE]).await?;
            let mut outbox = fixture.outbox(
                GlobalChunkAllocator,
                ControlledWriter {
                    fail_write,
                    fail_flush: !fail_write,
                    ..Default::default()
                },
            );
            outbox.push(Output::Offline {
                backlog: fixture.backlog().await?,
                handler: Arc::new(Offline::new(Default::default())),
            });
            assert_eq!(outbox.flush().await, Err(CloseOutcome::TransportError));
            assert_eq!(fixture.count().await?, 2);
            outbox.writer.fail_write = false;
            outbox.writer.fail_flush = false;
            flush_and_ack(&fixture, &mut outbox).await?;
            assert_eq!(fixture.count().await?, 0);
            drop(outbox);
            fixture.finish().await?;
        }
        Ok(())
    })
}

#[test]
fn replay_parses_only_one_arena_at_a_time_beyond_mailbox_capacity() -> TestResult {
    Runtime::new()?.block_on(async {
        let messages: Vec<&[u8]> = (0..80).map(|_| MESSAGE).collect();
        let fixture = Fixture::new(&messages).await?;
        let pool = Arc::new(PooledChunkAllocator::try_new(PoolConfig {
            total_bytes: NonZeroUsize::new(8 * 1024 * 1024).ok_or("invalid pool size")?,
            shards_per_bucket: NonZeroUsize::MIN,
        })?);
        let mut outbox = fixture.outbox(
            pool.clone(),
            ControlledWriter {
                pool: Some(pool.clone()),
                ..Default::default()
            },
        );
        flush_and_ack(&fixture, &mut outbox).await?;
        assert_eq!(outbox.writer.written.len(), 80);
        assert!(
            outbox.writer.maximum_chunks <= 3,
            "{} live chunks",
            outbox.writer.maximum_chunks
        );
        assert_eq!(pool.stats().heap_allocation_count, 0);
        assert_eq!(fixture.count().await?, 0);
        drop(outbox);
        fixture.finish().await
    })
}

#[test]
fn corrupt_records_are_skipped_but_whitespace_and_original_full_targets_are_preserved() -> TestResult
{
    Runtime::new()?.block_on(async {
        let messages: &[&[u8]] = &[
            b"",
            b"<message",
            b"<presence xmlns='jabber:client' to='bob@localhost'/>",
            b"<message xmlns='jabber:server' to='bob@localhost'/>",
            b"<message xmlns='jabber:client' to='bob@localhost' type='headline'/>",
            b"<message xmlns='jabber:client' to='alice@localhost'/>",
            b"<message xmlns='jabber:client' to='bob@localhost'/><message to='bob@localhost'/>",
            b"<message xmlns='jabber:client' to='bob@localhost'/>junk",
            b"<message xmlns='jabber:client' to='bob@localhost'/></stream:stream>",
            b"<message xmlns='jabber:client' to='bob@localhost'/> <message",
            b"<message xmlns='jabber:client' to='bob@localhost/old' type='chat' id='valid'/> \t\r\n",
        ];
        let fixture = Fixture::new(messages).await?;
        let mut outbox = fixture.outbox(GlobalChunkAllocator, ControlledWriter::default());
        flush_and_ack(&fixture, &mut outbox).await?;
        assert_eq!(outbox.writer.written.len(), 1);
        assert!(outbox.writer.written[0].contains("bob@localhost/old"));
        assert_eq!(fixture.count().await?, 0);
        drop(outbox);
        fixture.finish().await
    })
}

#[derive(Clone)]
struct FailingAllocator(Arc<AtomicBool>);

// Successful blocks retain the global allocator's ownership contract.
unsafe impl ChunkAllocator for FailingAllocator {
    fn allocate(&self, layout: Layout) -> Result<Chunk, AllocationError> {
        if self.0.load(Ordering::Acquire) {
            Err(AllocationError::Exhausted)
        } else {
            GlobalChunkAllocator.allocate(layout)
        }
    }
    unsafe fn deallocate(&self, chunk: Chunk) {
        unsafe { GlobalChunkAllocator.deallocate(chunk) };
    }
}

#[test]
fn valid_message_allocation_failure_keeps_the_stored_copy() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(&[MESSAGE, MESSAGE]).await?;
        let failure = Arc::new(AtomicBool::new(false));
        let mut outbox = fixture.outbox(
            FailingAllocator(failure.clone()),
            ControlledWriter {
                fail_allocation_after_write: Some(failure),
                ..Default::default()
            },
        );
        outbox.push(Output::Offline {
            backlog: fixture.backlog().await?,
            handler: Arc::new(Offline::new(Default::default())),
        });
        assert!(outbox.flush().await.is_err());
        assert_eq!(fixture.count().await?, 2);
        assert_eq!(outbox.writer.written.len(), 1);
        drop(outbox);
        fixture.finish().await
    })
}

#[test]
fn acknowledgement_waiting_for_a_writer_cannot_delete_a_recreated_accounts_sequence_one()
-> TestResult {
    let capture = crate::logging::tests::Capture::new()?;
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(&[MESSAGE]).await?;
        let owner = fixture.registration.account();
        let mut lifecycle = fixture.storage.begin_write().await?;
        let liveness = fixture.registration.liveness();
        let handler = Offline::new(Default::default());
        let watermark = Cell::new(OfflineSequence::new(1));
        let pending = acknowledge_backlog::<GlobalChunkAllocator>(
            &fixture.storage,
            owner,
            &liveness,
            &handler,
            &watermark,
        );
        let mut pending = Box::pin(pending);
        assert!(poll!(pending.as_mut()).is_pending());
        lifecycle.delete_account(owner).await?;
        lifecycle.clear_offline_messages(owner).await?;
        fixture.router.handle().retire_account(owner).await?;
        lifecycle
            .create_account(NewAccount {
                key: owner.clone(),
                credentials: credentials(),
            })
            .await?;
        let fresh = lifecycle.push_offline_message(owner, 1, MESSAGE).await?;
        assert_eq!(fresh.get(), 1);
        lifecycle.commit().await?;
        pending.await.map_err(|error| format!("{error:?}"))?;
        assert_eq!(capture.count("outcome=\"skipped_stale_session\"")?, 1);
        assert_eq!(capture.count("outcome=\"committed\"")?, 0);
        assert_eq!(fixture.count().await?, 1);
        fixture.finish().await
    })
}

#[test]
fn repeated_successful_flushes_coalesce_into_one_worker_and_the_highest_watermark() -> TestResult {
    Runtime::new()?.block_on(async {
        let messages: Vec<&[u8]> = (0..80).map(|_| MESSAGE).collect();
        let fixture = Fixture::new(&messages).await?;
        let writer = fixture.storage.begin_write().await?;
        let (done, acknowledged) = oneshot::channel();
        let handler = Arc::new(AckNotice(Mutex::new(Some(done))));
        let mut outbox = fixture.outbox(GlobalChunkAllocator, ControlledWriter::default());
        let mut identity = None;
        for message in fixture.backlog().await?.messages {
            outbox.push(Output::Offline {
                backlog: Backlog {
                    through: message.sequence,
                    messages: vec![message],
                },
                handler: handler.clone(),
            });
            outbox.flush().await.map_err(|error| format!("{error:?}"))?;
            let worker = outbox
                .acknowledgement
                .as_ref()
                .ok_or("missing acknowledgement worker")?;
            assert!(!worker.task.is_finished());
            let original = identity.get_or_insert_with(|| worker.through.clone());
            assert!(Rc::ptr_eq(original, &worker.through));
            assert!(Rc::strong_count(&worker.through) <= 3);
        }
        assert_eq!(
            outbox
                .acknowledgement
                .as_ref()
                .ok_or("missing worker")?
                .through
                .get()
                .get(),
            80
        );
        drop(writer);
        acknowledged.await?;
        drop(fixture.storage.begin_write().await?);
        assert_eq!(fixture.count().await?, 0);
        assert_eq!(outbox.writer.written.len(), 80);
        drop(outbox);
        fixture.finish().await
    })
}

#[test]
fn dropping_the_outbox_cancels_its_pending_acknowledgement_and_replay_can_retry() -> TestResult {
    let capture = crate::logging::tests::Capture::new()?;
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(&[MESSAGE]).await?;
        let writer = fixture.storage.begin_write().await?;
        let (done, acknowledged) = oneshot::channel();
        let mut outbox = fixture.outbox(GlobalChunkAllocator, ControlledWriter::default());
        outbox.push(Output::Offline {
            backlog: fixture.backlog().await?,
            handler: Arc::new(AckNotice(Mutex::new(Some(done)))),
        });
        outbox.flush().await.map_err(|error| format!("{error:?}"))?;
        (&mut outbox
            .acknowledgement
            .as_mut()
            .ok_or("missing worker")?
            .entered)
            .await?;
        drop(outbox);
        assert!(acknowledged.await.is_err());
        assert_eq!(capture.count("offline replay flushed")?, 1);
        assert_eq!(capture.count("outcome=\"committed\"")?, 0);
        drop(writer);
        assert_eq!(fixture.count().await?, 1);
        let mut retry = fixture.outbox(GlobalChunkAllocator, ControlledWriter::default());
        flush_and_ack(&fixture, &mut retry).await?;
        assert_eq!(fixture.count().await?, 0);
        assert_eq!(capture.count("offline replay flushed")?, 2);
        assert_eq!(capture.count("outcome=\"committed\"")?, 1);
        drop(retry);
        fixture.finish().await
    })
}

#[test]
fn writer_waiting_acknowledgement_does_not_stop_a_healthy_resource_from_draining_live_messages()
-> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(&[MESSAGE]).await?;
        let writer = fixture.storage.begin_write().await?;
        let (done, acknowledged) = oneshot::channel();
        let mut outbox = fixture.outbox(GlobalChunkAllocator, ControlledWriter::default());
        outbox.push(Output::Offline {
            backlog: fixture.backlog().await?,
            handler: Arc::new(AckNotice(Mutex::new(Some(done)))),
        });
        outbox.flush().await.map_err(|error| format!("{error:?}"))?;
        for _ in 0..80 {
            let stanza = outbox
                .parse_stored(
                    b"<message xmlns='jabber:client' to='bob@localhost/phone'/>",
                    StoredKind::Message,
                )
                .await
                .map_err(|_| "invalid live message")?;
            fixture.router.handle().route_full(stanza).await?;
            let live = fixture
                .registration
                .recv()
                .await
                .ok_or("missing live delivery")?;
            outbox
                .drain_mailbox(&fixture.registration, live)
                .await
                .map_err(|error| format!("{error:?}"))?;
        }
        assert_eq!(outbox.writer.written.len(), 81);
        assert!(fixture.registration.liveness().is_alive());
        drop(writer);
        acknowledged.await?;
        drop(fixture.storage.begin_write().await?);
        assert_eq!(fixture.count().await?, 0);
        drop(outbox);
        fixture.finish().await
    })
}

#[test]
fn acknowledgement_preserves_a_message_stored_after_the_replay_snapshot() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(&[MESSAGE]).await?;
        let backlog = fixture.backlog().await?;
        let mut writer = fixture.storage.begin_write().await?;
        let fresh = writer
            .push_offline_message(fixture.registration.account(), 1, MESSAGE)
            .await?;
        assert_eq!(fresh.get(), 2);
        let (done, acknowledged) = oneshot::channel();
        let mut outbox = fixture.outbox(GlobalChunkAllocator, ControlledWriter::default());
        outbox.push(Output::Offline {
            backlog,
            handler: Arc::new(AckNotice(Mutex::new(Some(done)))),
        });
        outbox.flush().await.map_err(|error| format!("{error:?}"))?;
        writer.commit().await?;
        acknowledged.await?;
        drop(fixture.storage.begin_write().await?);
        let remaining = fixture.backlog().await?;
        assert_eq!(remaining.messages.len(), 1);
        assert_eq!(remaining.messages[0].sequence, fresh);
        drop(outbox);
        fixture.finish().await
    })
}

struct ControlledAcknowledgement {
    fail: AtomicBool,
    calls: AtomicUsize,
}

impl<A: ChunkAllocator> MessageHandler<A, RedbStorage> for ControlledAcknowledgement {
    fn acknowledge<'a>(
        &'a self,
        account: &'a AccountKey,
        through: OfflineSequence,
        transaction: &'a mut lonewolf_storage::RedbWrite,
    ) -> lonewolf_extension::ExtensionFuture<'a, Result<(), HandlerError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.fail.load(Ordering::Acquire) {
                return Err(StanzaErrorCondition::InternalServerError.into());
            }
            <Offline as MessageHandler<A, RedbStorage>>::acknowledge(
                &Offline::new(Default::default()),
                account,
                through,
                transaction,
            )
            .await
        })
    }
}

#[test]
fn failed_acknowledgement_logs_once_and_restarts_for_the_same_watermark_after_a_later_flush()
-> TestResult {
    let log = tempfile::NamedTempFile::new()?;
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(Mutex::new(log.reopen()?))
        .finish();
    let _subscriber = tracing::subscriber::set_default(subscriber);
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(&[MESSAGE]).await?;
        let handler = Arc::new(ControlledAcknowledgement {
            fail: AtomicBool::new(true),
            calls: AtomicUsize::new(0),
        });
        let mut outbox = fixture.outbox(GlobalChunkAllocator, ControlledWriter::default());
        outbox.push(Output::Offline {
            backlog: fixture.backlog().await?,
            handler: handler.clone(),
        });
        outbox.flush().await.map_err(|error| format!("{error:?}"))?;
        (&mut outbox
            .acknowledgement
            .as_mut()
            .ok_or("missing worker")?
            .task)
            .await?;
        assert_eq!(fixture.count().await?, 1);
        for _ in 0..10 {
            outbox.flush().await.map_err(|error| format!("{error:?}"))?;
        }
        assert_eq!(handler.calls.load(Ordering::Relaxed), 1);
        assert!(!std::fs::read_to_string(log.path())?.contains("outcome=\"committed\""));
        assert!(
            outbox
                .acknowledgement
                .as_ref()
                .ok_or("missing worker")?
                .task
                .is_finished()
        );
        handler.fail.store(false, Ordering::Release);
        outbox.push(Output::Offline {
            backlog: fixture.backlog().await?,
            handler: handler.clone(),
        });
        outbox.flush().await.map_err(|error| format!("{error:?}"))?;
        (&mut outbox
            .acknowledgement
            .as_mut()
            .ok_or("missing retry worker")?
            .task)
            .await?;
        assert_eq!(handler.calls.load(Ordering::Relaxed), 2);
        assert_eq!(fixture.count().await?, 0);
        let logs = std::fs::read_to_string(log.path())?;
        assert_eq!(
            logs.matches("offline backlog acknowledgement failed")
                .count(),
            1
        );
        assert_eq!(logs.matches("outcome=\"committed\"").count(), 1);
        drop(outbox);
        fixture.finish().await
    })
}
