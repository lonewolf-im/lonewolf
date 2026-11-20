// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use compio::runtime::Runtime;
use futures_channel::oneshot;
use futures_util::FutureExt;
use futures_util::future::{Either, select};
use lonewolf_extension::archive::{
    ArchiveDirection, ArchiveFuture, ArchiveHandler, ArchiveId, ArchiveOutcome, ArchiveRequest,
};
use lonewolf_extension::blocking::{Blocking, NAME as BLOCKING};
use lonewolf_extension::delivery::{Delivery, DeliveryError, DeliveryFuture, SessionId};
use lonewolf_extension::observer::{MessageEvent, MessageObserver, MessageOutcome, MessageRole};
use lonewolf_extension::policy::{Direction, PolicyFuture, PolicyHandler, PolicyRequest, Verdict};
use lonewolf_extension::{Extension, Extensions, RegistrationError, Slots};
use lonewolf_storage::{RedbRead, RedbStorage, RedbWrite};
use lonewolf_util::arena::{Arena, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::{
    MessageType, PresenceType, Stanza, StanzaErrorCondition, StanzaNamespace, StanzaType,
};
use parking_lot::Mutex as PlMutex;

use super::{TestResult, account, stanza};
use crate::config::Config;
use crate::delivery::{WorkGroup, WorkHandle};
use crate::hosts::Hosts;
use crate::router::local::LocalRouter;
use crate::router::metrics::MessageOutcome as MetricOutcome;
use crate::router::{Router, RouterHandle};
use crate::stages::Stage;
use crate::stages::ingress::Origin;
use crate::stages::ingress::message::handle_from;
use crate::stages::ingress::message::{MessageDisposition, Reply, handle};
use crate::stages::message::MissingRecipientPolicy;

type ObserverGate = (oneshot::Sender<()>, oneshot::Receiver<()>);

#[derive(Debug, PartialEq)]
enum Call {
    Policy(String, Direction),
    Archive(String, ArchiveDirection),
    Observe {
        account: String,
        role: MessageRole,
        outcome: MessageOutcome,
        archived: Option<ArchiveId>,
        holders: Vec<SessionId>,
        rejection: bool,
    },
}

struct Recorder {
    verdict: Verdict,
    archive_rejects: bool,
    observer_fails: bool,
    calls: PlMutex<Vec<Call>>,
    checking: PlMutex<Option<oneshot::Sender<()>>>,
    observing: PlMutex<Option<ObserverGate>>,
}

impl Extension<GlobalChunkAllocator, RedbStorage> for Recorder {
    fn name(&self) -> &'static str {
        "pipeline-recorder"
    }
    fn register(
        self: Arc<Self>,
        _: &str,
        slots: &mut Slots<'_, GlobalChunkAllocator, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.policy(self.clone());
        slots.archive(self.clone())?;
        slots.message_observer(self);
        Ok(())
    }
}

impl PolicyHandler<RedbStorage> for Recorder {
    fn check<'a>(&'a self, request: PolicyRequest<'a>, _: &'a RedbRead) -> PolicyFuture<'a> {
        self.calls.lock().push(Call::Policy(
            request.account.as_str().into(),
            request.direction,
        ));
        if let Some(checking) = self.checking.lock().take() {
            let _ = checking.send(());
        }
        Box::pin(async move { Ok(self.verdict) })
    }
}

impl ArchiveHandler<GlobalChunkAllocator, RedbStorage> for Recorder {
    fn selects(&self, _: &ArchiveRequest<'_, GlobalChunkAllocator>) -> bool {
        true
    }
    fn archive<'a>(
        &'a self,
        request: ArchiveRequest<'a, GlobalChunkAllocator>,
        _: &'a mut RedbWrite,
        _: &'a mut Arena<GlobalChunkAllocator>,
    ) -> ArchiveFuture<'a> {
        self.calls.lock().push(Call::Archive(
            request.owner.as_str().into(),
            request.direction,
        ));
        Box::pin(async move {
            if self.archive_rejects {
                Err(StanzaErrorCondition::NotAcceptable.into())
            } else {
                Ok(ArchiveOutcome::Archived(ArchiveId::new(
                    match request.direction {
                        ArchiveDirection::Sent => 7,
                        ArchiveDirection::Received => 8,
                    },
                )))
            }
        })
    }
}

impl MessageObserver<GlobalChunkAllocator, RedbStorage> for Recorder {
    fn observe<'a>(
        &'a self,
        event: MessageEvent<'a, GlobalChunkAllocator>,
        _: &'a RedbStorage,
        _: &'a dyn Delivery<GlobalChunkAllocator>,
    ) -> DeliveryFuture<'a> {
        self.calls.lock().push(Call::Observe {
            account: event.account.as_str().into(),
            role: event.role,
            outcome: event.outcome,
            archived: event.archived,
            holders: event.holders.to_vec(),
            rejection: event.rejection.is_some(),
        });
        let gate = self.observing.lock().take();
        Box::pin(async move {
            if let Some((entered, resume)) = gate {
                let _ = entered.send(());
                resume.await.map_err(|_| DeliveryError)?;
            }
            if self.observer_fails {
                Err(DeliveryError)
            } else {
                Ok(())
            }
        })
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    storage: RedbStorage,
    router: Router<GlobalChunkAllocator>,
    handle: RouterHandle<GlobalChunkAllocator>,
    work: WorkHandle,
    recorder: Arc<Recorder>,
}

impl Fixture {
    fn new(verdict: Verdict, archive_rejects: bool, observer_fails: bool) -> TestResult<Self> {
        Self::configured(verdict, archive_rejects, observer_fails, false)
    }

    fn configured(
        verdict: Verdict,
        archive_rejects: bool,
        observer_fails: bool,
        blocking: bool,
    ) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
        let recorder = Arc::new(Recorder {
            verdict,
            archive_rejects,
            observer_fails,
            calls: PlMutex::new(Vec::new()),
            checking: PlMutex::new(None),
            observing: PlMutex::new(None),
        });
        let mut extensions = Extensions::default();
        extensions.register(recorder.clone())?;
        extensions.register(Arc::new(Blocking))?;
        let names = if blocking {
            &[BLOCKING, "pipeline-recorder"][..]
        } else {
            &["pipeline-recorder"][..]
        };
        let router = Router::new(
            Hosts::new(&Config::default().hosts, None)?,
            LocalRouter::new(GlobalChunkAllocator),
        )
        .with_extensions(BTreeMap::from([(
            "localhost".into(),
            extensions.enable_host("localhost", names.iter().copied())?,
        )]));
        let handle = router.handle();
        Ok(Self {
            _directory: directory,
            storage,
            router,
            handle,
            work: WorkGroup::new().handle(),
            recorder,
        })
    }
    fn stage(&self) -> Stage<'_, GlobalChunkAllocator> {
        Stage {
            router: &self.handle,
            storage: &self.storage,
            allocator: &GlobalChunkAllocator,
            work: &self.work,
        }
    }
}

#[test]
fn admitted_message_finishes_both_observers_after_sender_retirement() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::configured(Verdict::Allow, false, false, true)?;
        let sender = account("alice@localhost")?;
        let recipient = account("bob@localhost")?;
        let origin = fixture
            .handle
            .register(&sender, Some("desk"), NonZeroUsize::MIN)
            .await?;
        let target = fixture
            .handle
            .register(&recipient, Some("phone"), NonZeroUsize::MIN)
            .await?;
        let origin_id = origin.session_id();
        let target_id = target.session_id();
        let (entered, observing) = oneshot::channel();
        let (resume, waiting) = oneshot::channel();
        *fixture.recorder.observing.lock() = Some((entered, waiting));
        let source = origin.handle();
        let message = stanza("alice@localhost/desk", "bob@localhost/phone")?;
        let service_router = fixture.handle.clone();
        let storage = fixture.storage.clone();
        let mut work = WorkGroup::new();
        let worker = work.handle();
        let pending = crate::delivery::Pending::spawn(work.start(), async move {
            let stage = Stage {
                router: &service_router,
                storage: &storage,
                allocator: &GlobalChunkAllocator,
                work: &worker,
            };
            handle_from(
                &stage,
                Some(&source),
                message,
                MessageType::Chat,
                MissingRecipientPolicy::Discard,
            )
            .await
        });
        observing.await?;
        assert_eq!(target.take_queued().len(), 1);
        fixture.handle.retire_account(&sender).await?;
        origin.wait_retired().await?;
        let replacement = fixture
            .handle
            .register(&sender, Some("desk"), NonZeroUsize::MIN)
            .await?;
        assert_ne!(replacement.session_id(), origin_id);
        drop(pending);
        resume.send(()).map_err(|_| "observer canceled")?;
        work.drain().await;
        let observations = fixture
            .recorder
            .calls
            .lock()
            .iter()
            .filter_map(|call| {
                if let Call::Observe {
                    role,
                    outcome,
                    holders,
                    ..
                } = call
                {
                    Some((*role, *outcome, holders.clone()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(
            observations,
            [
                (MessageRole::Sent, MessageOutcome::Routed, vec![origin_id]),
                (
                    MessageRole::Received,
                    MessageOutcome::Routed,
                    vec![target_id]
                ),
            ]
        );
        drop((replacement, origin, target));
        fixture.router.shutdown().await?;
        Ok(())
    }))?
}

#[test]
fn retired_sender_cannot_admit_message_with_its_replacement_address() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::configured(Verdict::Allow, false, false, true)?;
        let sender = account("alice@localhost")?;
        let recipient = account("bob@localhost")?;
        let stale = fixture
            .handle
            .register(&sender, Some("desk"), NonZeroUsize::MIN)
            .await?;
        let target = fixture
            .handle
            .register(&recipient, Some("phone"), NonZeroUsize::MIN)
            .await?;
        let ((), mut blocker) = fixture
            .handle
            .order()
            .fix(vec![sender.clone()], async {
                Ok::<_, crate::stages::StageFailure>(())
            })
            .await
            .map_err(|_| "could not fix admission ticket")?;
        blocker.turn().await;
        let (checking, checked) = oneshot::channel();
        *fixture.recorder.checking.lock() = Some(checking);
        let stage = fixture.stage();
        let source = Origin::Session(&stale);
        let message = stanza("alice@localhost/desk", "bob@localhost/phone")?;
        let mut pending = Box::pin(handle(&stage, &source, message.clone(), MessageType::Chat));
        match select(checked, pending.as_mut()).await {
            Either::Left((signal, _)) => signal?,
            Either::Right(_) => return Err("message completed before the admission ticket".into()),
        }
        fixture.handle.retire_account(&sender).await?;
        stale.wait_retired().await?;
        let replacement = fixture
            .handle
            .register(&sender, Some("desk"), NonZeroUsize::MIN)
            .await?;
        assert_eq!(stale.full_jid(), replacement.full_jid());
        assert_ne!(stale.session_id(), replacement.session_id());
        drop(blocker);
        assert!(matches!(
            pending.await.map_err(|_| "message stage")?,
            MessageDisposition::Done
        ));
        assert!(target.take_queued().is_empty());
        assert!(
            fixture
                .recorder
                .calls
                .lock()
                .iter()
                .all(|call| matches!(call, Call::Policy(_, _)))
        );
        fixture.recorder.calls.lock().clear();

        let live = Origin::Session(&replacement);
        assert!(matches!(
            handle(&stage, &live, message, MessageType::Chat)
                .await
                .map_err(|_| "message stage")?,
            MessageDisposition::Done
        ));
        assert_eq!(target.take_queued().len(), 1);
        assert!(
            fixture
                .recorder
                .calls
                .lock()
                .iter()
                .any(|call| matches!(call, Call::Archive(_, _)))
        );
        assert!(
            fixture
                .recorder
                .calls
                .lock()
                .iter()
                .any(|call| matches!(call, Call::Observe { .. }))
        );
        drop((replacement, stale, target));
        fixture.router.shutdown().await?;
        Ok(())
    }))?
}

#[test]
fn origins_share_policy_archive_delivery_and_observer_composition() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new(Verdict::Allow, false, false)?;
        let sender = account("alice@localhost")?;
        let session = fixture
            .handle
            .register(&sender, Some("desk"), NonZeroUsize::MIN)
            .await?;
        let recipient = fixture
            .handle
            .register(&account("bob@localhost")?, Some("phone"), NonZeroUsize::MIN)
            .await?;
        let mut arena = Arena::try_new(Default::default())?;
        let from = Jid::parse_in("bob@localhost/phone", &mut arena)?;
        let presence = Stanza::builder_in(
            StanzaType::Presence(PresenceType::Available),
            StanzaNamespace::Client,
            &mut arena,
        )
        .from(Some(from))?
        .build()?;
        recipient
            .handle()
            .set_presence(
                Some(0),
                lonewolf_xmpp::stanza::RoutedStanza::from_parts(presence, arena),
                None,
            )
            .await?;
        for origin in [
            Origin::Session(&session),
            Origin::Remote {
                local: "localhost",
                remote: "remote.test",
            },
            Origin::Service {
                domain: "service.test",
            },
        ] {
            let from = match origin {
                Origin::Session(_) => "alice@localhost/desk",
                Origin::Remote { .. } => "alice@remote.test/desk",
                Origin::Service { .. } => "service.test",
            };
            for to in ["bob@localhost", "bob@localhost/phone", "localhost"] {
                let local_recipient = to != "localhost";
                let disposition = handle(
                    &fixture.stage(),
                    &origin,
                    stanza(from, to)?,
                    MessageType::Chat,
                )
                .await
                .map_err(|_| "pipeline failed")?;
                let mut expected = Vec::new();
                if origin.session().is_some() {
                    expected.push(Call::Policy("alice@localhost".into(), Direction::Outbound));
                }
                if local_recipient {
                    expected.push(Call::Policy("bob@localhost".into(), Direction::Inbound));
                }
                if origin.session().is_some() {
                    expected.push(Call::Archive(
                        "alice@localhost".into(),
                        ArchiveDirection::Sent,
                    ));
                }
                if local_recipient {
                    expected.push(Call::Archive(
                        "bob@localhost".into(),
                        ArchiveDirection::Received,
                    ));
                }
                if origin.session().is_some() {
                    expected.push(Call::Observe {
                        account: "alice@localhost".into(),
                        role: MessageRole::Sent,
                        outcome: if local_recipient {
                            MessageOutcome::Routed
                        } else {
                            MessageOutcome::Rejected
                        },
                        archived: Some(ArchiveId::new(7)),
                        holders: vec![session.session_id()],
                        rejection: !local_recipient,
                    });
                }
                if local_recipient {
                    expected.push(Call::Observe {
                        account: "bob@localhost".into(),
                        role: MessageRole::Received,
                        outcome: MessageOutcome::Routed,
                        archived: Some(ArchiveId::new(8)),
                        holders: vec![recipient.session_id()],
                        rejection: false,
                    });
                    assert!(matches!(disposition, MessageDisposition::Done));
                    let delivered = recipient.recv().await.ok_or("missing delivered message")?;
                    assert_eq!(
                        delivered
                            .stanza
                            .resolve()?
                            .from()?
                            .ok_or("sender")?
                            .as_str(),
                        from
                    );
                    assert_eq!(
                        delivered
                            .stanza
                            .resolve()?
                            .to()?
                            .ok_or("recipient")?
                            .as_str(),
                        to
                    );
                } else if origin.session().is_some() {
                    assert!(matches!(
                        disposition,
                        MessageDisposition::Reply(Reply::Built(_))
                    ));
                } else {
                    assert!(matches!(
                        disposition,
                        MessageDisposition::Reply(Reply::Error { .. })
                    ));
                }
                assert_eq!(*fixture.recorder.calls.lock(), expected);
                fixture.recorder.calls.lock().clear();
            }
        }
        assert_eq!(fixture.handle.metrics().messages(MetricOutcome::Routed), 6);
        assert_eq!(
            fixture.handle.metrics().messages(MetricOutcome::Rejected),
            3
        );
        assert_eq!(fixture.handle.metrics().messages(MetricOutcome::Failed), 0);
        drop(recipient);
        drop(session);
        fixture.router.shutdown().await?;
        Ok(())
    }))?
}

#[test]
fn policy_drop_stops_archive_delivery_and_observers() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(Verdict::Drop, false, false)?;
        let sender = account("alice@localhost")?;
        let session = fixture
            .handle
            .register(&sender, Some("desk"), NonZeroUsize::MIN)
            .await?;
        for origin in [
            Origin::Session(&session),
            Origin::Remote {
                local: "localhost",
                remote: "remote.test",
            },
            Origin::Service {
                domain: "service.test",
            },
        ] {
            let from = match origin {
                Origin::Session(_) => "alice@localhost/desk",
                Origin::Remote { .. } => "alice@remote.test/desk",
                Origin::Service { .. } => "service.test",
            };
            let disposition = handle(
                &fixture.stage(),
                &origin,
                stanza(from, "bob@localhost/phone")?,
                MessageType::Chat,
            )
            .await
            .map_err(|_| "pipeline failed")?;
            assert!(matches!(disposition, MessageDisposition::Done));
            assert_eq!(
                *fixture.recorder.calls.lock(),
                [Call::Policy(
                    if origin.session().is_some() {
                        "alice@localhost"
                    } else {
                        "bob@localhost"
                    }
                    .into(),
                    if origin.session().is_some() {
                        Direction::Outbound
                    } else {
                        Direction::Inbound
                    }
                )]
            );
            fixture.recorder.calls.lock().clear();
        }
        for outcome in MetricOutcome::ALL {
            assert_eq!(fixture.handle.metrics().messages(outcome), 0);
        }
        drop(session);
        fixture.router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn policy_and_archive_rejections_return_before_delivery_and_observers() -> TestResult {
    Runtime::new()?.block_on(async {
        for archive_rejects in [false, true] {
            let fixture = Fixture::new(
                if archive_rejects {
                    Verdict::Allow
                } else {
                    Verdict::Reject {
                        condition: StanzaErrorCondition::Forbidden,
                        application: None,
                        text: None,
                    }
                },
                archive_rejects,
                false,
            )?;
            let origin = Origin::Remote {
                local: "localhost",
                remote: "remote.test",
            };
            let disposition = handle(
                &fixture.stage(),
                &origin,
                stanza("alice@remote.test/desk", "bob@localhost/phone")?,
                MessageType::Chat,
            )
            .await
            .map_err(|_| "pipeline failed")?;
            match disposition {
                MessageDisposition::Reply(Reply::Error {
                    condition,
                    application,
                    text,
                    ..
                }) => {
                    assert_eq!(
                        condition,
                        if archive_rejects {
                            StanzaErrorCondition::NotAcceptable
                        } else {
                            StanzaErrorCondition::Forbidden
                        }
                    );
                    assert!(application.is_none());
                    assert_eq!(text, condition.default_text());
                }
                _ => return Err("expected early rejection".into()),
            }
            let mut expected = vec![Call::Policy("bob@localhost".into(), Direction::Inbound)];
            if archive_rejects {
                expected.push(Call::Archive(
                    "bob@localhost".into(),
                    ArchiveDirection::Received,
                ));
            }
            assert_eq!(*fixture.recorder.calls.lock(), expected);
            for outcome in MetricOutcome::ALL {
                assert_eq!(fixture.handle.metrics().messages(outcome), 0);
            }
            fixture.router.shutdown().await?;
        }
        Ok(())
    })
}

#[test]
fn observer_failures_preserve_delivery_and_its_single_metric() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new(Verdict::Allow, false, true)?;
        let recipient = fixture
            .handle
            .register(&account("bob@localhost")?, Some("phone"), NonZeroUsize::MIN)
            .await?;
        let origin = Origin::Remote {
            local: "localhost",
            remote: "remote.test",
        };
        let disposition = handle(
            &fixture.stage(),
            &origin,
            stanza("alice@remote.test/desk", "bob@localhost/phone")?,
            MessageType::Chat,
        )
        .await
        .map_err(|_| "pipeline failed")?;
        assert!(matches!(disposition, MessageDisposition::Done));
        assert!(recipient.recv().now_or_never().flatten().is_some());
        assert_eq!(fixture.handle.metrics().messages(MetricOutcome::Routed), 1);
        assert!(matches!(
            fixture.recorder.calls.lock().last(),
            Some(Call::Observe {
                role: MessageRole::Received,
                outcome: MessageOutcome::Routed,
                ..
            })
        ));
        drop(recipient);
        fixture.router.shutdown().await?;
        Ok(())
    }))?
}

#[test]
fn missing_recipient_rejections_depend_on_origin_and_record_one_delivery_outcome() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let mut fixture = Fixture::new(Verdict::Allow, false, false)?;
        let mut extensions = Extensions::default();
        extensions.register(Arc::new(lonewolf_extension::offline::Offline::new(
            BTreeMap::new(),
        )))?;
        fixture.router = fixture.router.with_extensions(BTreeMap::from([(
            "localhost".into(),
            extensions.enable_host("localhost", ["offline"])?,
        )]));
        fixture.handle = fixture.router.handle();
        let sender = account("alice@localhost")?;
        let session = fixture
            .handle
            .register(&sender, Some("desk"), NonZeroUsize::MIN)
            .await?;
        for kind in [MessageType::Normal, MessageType::Chat] {
            for origin in [
                Origin::Session(&session),
                Origin::Remote {
                    local: "localhost",
                    remote: "remote.test",
                },
                Origin::Service {
                    domain: "service.test",
                },
            ] {
                let from = match origin {
                    Origin::Session(_) => "alice@localhost/desk",
                    Origin::Remote { .. } => "alice@remote.test/desk",
                    Origin::Service { .. } => "service.test",
                };
                let mut arena = Arena::try_new(Default::default())?;
                let sender = Jid::parse_in(from, &mut arena)?;
                let target = Jid::parse_in("unknown@localhost", &mut arena)?;
                let stanza = Stanza::builder_in(
                    StanzaType::Message(kind),
                    StanzaNamespace::Client,
                    &mut arena,
                )
                .from(Some(sender))?
                .to(Some(target))?
                .build()?;
                let routed = lonewolf_xmpp::stanza::RoutedStanza::from_parts(stanza, arena);
                let mut expected = String::new();
                routed.resolve()?.write_xml(&mut expected)?;
                let before =
                    MetricOutcome::ALL.map(|outcome| fixture.handle.metrics().messages(outcome));
                let disposition = handle(&fixture.stage(), &origin, routed, kind)
                    .await
                    .map_err(|_| "missing-recipient delivery failed")?;
                let outcome = if matches!(origin, Origin::Service { .. }) {
                    let MessageDisposition::Reply(Reply::Error {
                        stanza,
                        condition,
                        application,
                        text,
                    }) = disposition
                    else {
                        return Err("service origin must reject a missing recipient".into());
                    };
                    assert_eq!(condition, StanzaErrorCondition::ServiceUnavailable);
                    assert!(application.is_none());
                    assert_eq!(text, condition.default_text());
                    let mut actual = String::new();
                    stanza.resolve()?.write_xml(&mut actual)?;
                    assert_eq!(actual, expected);
                    MetricOutcome::Rejected
                } else {
                    assert!(matches!(disposition, MessageDisposition::Done));
                    MetricOutcome::Discarded
                };
                for (candidate, before) in MetricOutcome::ALL.into_iter().zip(before) {
                    assert_eq!(
                        fixture.handle.metrics().messages(candidate),
                        before + u64::from(candidate == outcome)
                    );
                }
            }
        }
        drop(session);
        fixture.router.shutdown().await?;
        Ok(())
    }))?
}
