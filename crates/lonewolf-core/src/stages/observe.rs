// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::observer::{MessageEvent, MessageOutcome, SessionChange};
use lonewolf_util::arena::ChunkAllocator;

use super::Stage;
use super::message::DeliveryOutcome;
use super::service::ServiceOutcome;
use crate::delivery::RouterDelivery;

pub(crate) async fn message<A: ChunkAllocator + Clone>(
    stage: &Stage<'_, A>,
    delivery: &RouterDelivery<A>,
    event: MessageEvent<'_, A>,
) {
    for (name, observer) in stage.router.message_observers(event.account.domain()) {
        if observer
            .observe(event, stage.storage, delivery)
            .await
            .is_err()
        {
            tracing::error!(
                failure_kind = "delivery",
                operation = "message_observer",
                extension = name,
                account_jid = ?event.account.as_str(),
                "internal operation failed"
            );
        }
    }
}

pub(crate) async fn session<A: ChunkAllocator + Clone>(
    stage: &Stage<'_, A>,
    delivery: &RouterDelivery<A>,
    change: SessionChange<'_, A>,
) {
    for (name, observer) in stage.router.session_observers(change.session.domainpart()) {
        if observer
            .session_changed(change, stage.storage, delivery)
            .await
            .is_err()
        {
            tracing::error!(
                failure_kind = "delivery",
                operation = "session_observer",
                extension = name,
                account_jid = ?change.session.bare().as_str(),
                "internal operation failed"
            );
        }
    }
}

impl<A: ChunkAllocator> From<&DeliveryOutcome<A>> for MessageOutcome {
    fn from(outcome: &DeliveryOutcome<A>) -> Self {
        match outcome {
            DeliveryOutcome::Routed { .. } => Self::Routed,
            DeliveryOutcome::Stored { .. } => Self::Stored,
            DeliveryOutcome::Discarded => Self::Discarded,
            DeliveryOutcome::Rejected { .. } => Self::Rejected,
        }
    }
}

impl<A: ChunkAllocator> From<&ServiceOutcome<A>> for MessageOutcome {
    fn from(outcome: &ServiceOutcome<A>) -> Self {
        match outcome {
            ServiceOutcome::Handled => Self::Forwarded,
            ServiceOutcome::Rejected { .. } => Self::Rejected,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::error::Error;
    use std::sync::Arc;

    use compio::runtime::Runtime;
    use lonewolf_extension::archive::ArchiveId;
    use lonewolf_extension::delivery::{Delivery, DeliveryError, DeliveryFuture, FailureKind};
    use lonewolf_extension::observer::{
        MessageObserver, MessageRole, SessionEvent, SessionObserver,
    };
    use lonewolf_extension::{Extension, Extensions, RegistrationError, Slots};
    use lonewolf_storage::RedbStorage;
    use lonewolf_storage::account::AccountKey;
    use lonewolf_util::arena::{Arena, GlobalChunkAllocator};
    use lonewolf_xmpp::jid::Jid;
    use lonewolf_xmpp::stanza::{MessageType, RoutedStanza, Stanza, StanzaNamespace, StanzaType};
    use parking_lot::Mutex as PlMutex;

    use super::*;
    use crate::config::Config;
    use crate::delivery::WorkGroup;
    use crate::delivery::failure_tests::Capture;
    use crate::hosts::Hosts;
    use crate::router::Router;
    use crate::router::local::LocalRouter;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;
    type Call = (
        &'static str,
        String,
        MessageRole,
        MessageOutcome,
        Option<ArchiveId>,
    );

    struct RecordingObserver {
        name: &'static str,
        fail: bool,
        calls: Arc<PlMutex<Vec<Call>>>,
    }

    impl Extension<GlobalChunkAllocator, RedbStorage> for RecordingObserver {
        fn name(&self) -> &'static str {
            self.name
        }

        fn register(
            self: Arc<Self>,
            _: &str,
            slots: &mut Slots<'_, GlobalChunkAllocator, RedbStorage>,
        ) -> Result<(), RegistrationError> {
            slots.message_observer(self);
            Ok(())
        }
    }

    impl MessageObserver<GlobalChunkAllocator, RedbStorage> for RecordingObserver {
        fn observe<'a>(
            &'a self,
            event: MessageEvent<'a, GlobalChunkAllocator>,
            _: &'a RedbStorage,
            _: &'a dyn Delivery<GlobalChunkAllocator>,
        ) -> DeliveryFuture<'a> {
            Box::pin(async move {
                self.calls.lock().push((
                    self.name,
                    event.account.as_str().into(),
                    event.role,
                    event.outcome,
                    event.archived,
                ));
                if self.fail {
                    Err(DeliveryError)
                } else {
                    Ok(())
                }
            })
        }
    }

    fn account(value: &str) -> TestResult<AccountKey> {
        let mut arena = Arena::try_new(Default::default())?;
        let jid = Jid::parse_in(value, &mut arena)?;
        Ok(AccountKey::try_from(jid.resolve(&arena)?)?)
    }

    #[test]
    fn observers_keep_host_enable_order_and_continue_after_failure() -> TestResult {
        Runtime::new()?.block_on(async {
            let directory = tempfile::tempdir()?;
            let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
            let config = Config::default();
            let hosts = Hosts::new(&config.hosts, None)?;
            let calls = Arc::new(PlMutex::new(Vec::new()));
            let mut extensions = Extensions::default();
            for (name, fail) in [("z-first", true), ("a-second", false)] {
                extensions.register(Arc::new(RecordingObserver {
                    name,
                    fail,
                    calls: Arc::clone(&calls),
                }))?;
            }
            let router = Router::new(hosts, LocalRouter::new(GlobalChunkAllocator))
                .with_extensions(BTreeMap::from([
                    (
                        "localhost".into(),
                        extensions.enable_host("localhost", ["z-first", "a-second"])?,
                    ),
                    (
                        "other.localhost".into(),
                        extensions.enable_host("other.localhost", ["a-second"])?,
                    ),
                ]));
            let handle = router.handle();
            assert!(handle.message_observers("unknown.localhost").is_empty());
            let work = WorkGroup::new().handle();
            let stage = Stage {
                router: &handle,
                storage: &storage,
                allocator: &GlobalChunkAllocator,
                work: &work,
            };
            let delivery = RouterDelivery::new(&handle, &GlobalChunkAllocator, None);
            let sender = account("alice@localhost")?;
            let recipient = account("bob@other.localhost")?;
            let mut arena = Arena::try_new(Default::default())?;
            let stanza = Stanza::builder_in(
                StanzaType::Message(MessageType::Chat),
                StanzaNamespace::Client,
                &mut arena,
            )
            .id(Some("private-client-stanza-id"))?
            .build()?;
            let stanza = RoutedStanza::from_parts(stanza, arena);
            let event = MessageEvent {
                account: &sender,
                role: MessageRole::Sent,
                stanza: &stanza,
                outcome: MessageOutcome::Routed,
                archived: Some(ArchiveId::new(7)),
                holders: &[],
                rejection: None,
            };
            let capture = Capture::default();
            let subscriber = tracing::subscriber::set_default(capture.clone());
            message(&stage, &delivery, event).await;
            message(
                &stage,
                &delivery,
                MessageEvent {
                    account: &recipient,
                    role: MessageRole::Received,
                    archived: Some(ArchiveId::new(8)),
                    ..event
                },
            )
            .await;
            drop(subscriber);
            capture.assert_one(FailureKind::Delivery, "message_observer");
            assert_eq!(
                *calls.lock(),
                [
                    (
                        "z-first",
                        "alice@localhost".into(),
                        MessageRole::Sent,
                        MessageOutcome::Routed,
                        Some(ArchiveId::new(7))
                    ),
                    (
                        "a-second",
                        "alice@localhost".into(),
                        MessageRole::Sent,
                        MessageOutcome::Routed,
                        Some(ArchiveId::new(7))
                    ),
                    (
                        "a-second",
                        "bob@other.localhost".into(),
                        MessageRole::Received,
                        MessageOutcome::Routed,
                        Some(ArchiveId::new(8))
                    ),
                ]
            );
            router.shutdown().await?;
            Ok(())
        })
    }

    struct RecordingSessionObserver {
        name: &'static str,
        fail: bool,
        calls: Arc<PlMutex<Vec<(&'static str, String)>>>,
    }

    impl Extension<GlobalChunkAllocator, RedbStorage> for RecordingSessionObserver {
        fn name(&self) -> &'static str {
            self.name
        }

        fn register(
            self: Arc<Self>,
            _: &str,
            slots: &mut Slots<'_, GlobalChunkAllocator, RedbStorage>,
        ) -> Result<(), RegistrationError> {
            slots.session_observer(self);
            Ok(())
        }
    }

    impl SessionObserver<GlobalChunkAllocator, RedbStorage> for RecordingSessionObserver {
        fn session_changed<'a>(
            &'a self,
            change: SessionChange<'a, GlobalChunkAllocator>,
            _: &'a RedbStorage,
            _: &'a dyn Delivery<GlobalChunkAllocator>,
        ) -> DeliveryFuture<'a> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .push((self.name, change.session.as_str().into()));
                if self.fail {
                    Err(DeliveryError)
                } else {
                    Ok(())
                }
            })
        }
    }

    #[test]
    fn session_observers_keep_host_enable_order_and_continue_after_failure() -> TestResult {
        Runtime::new()?.block_on(async {
            let directory = tempfile::tempdir()?;
            let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
            let config = Config::default();
            let hosts = Hosts::new(&config.hosts, None)?;
            let calls = Arc::new(PlMutex::new(Vec::new()));
            let mut extensions = Extensions::default();
            for (name, fail) in [("z-first", true), ("a-second", false)] {
                extensions.register(Arc::new(RecordingSessionObserver {
                    name,
                    fail,
                    calls: Arc::clone(&calls),
                }))?;
            }
            let router = Router::new(hosts, LocalRouter::new(GlobalChunkAllocator))
                .with_extensions(BTreeMap::from([
                    (
                        "localhost".into(),
                        extensions.enable_host("localhost", ["z-first", "a-second"])?,
                    ),
                    (
                        "other.localhost".into(),
                        extensions.enable_host("other.localhost", ["a-second"])?,
                    ),
                ]));
            let handle = router.handle();
            assert!(handle.session_observers("unknown.localhost").is_empty());
            let work = WorkGroup::new().handle();
            let stage = Stage {
                router: &handle,
                storage: &storage,
                allocator: &GlobalChunkAllocator,
                work: &work,
            };
            let delivery = RouterDelivery::new(&handle, &GlobalChunkAllocator, None);
            let mut arena = Arena::try_new(Default::default())?;
            let first = Jid::parse_in("alice@localhost/a", &mut arena)?;
            let second = Jid::parse_in("bob@other.localhost/b", &mut arena)?;
            let unknown = Jid::parse_in("carol@unknown.localhost/c", &mut arena)?;
            let capture = Capture::default();
            let subscriber = tracing::subscriber::set_default(capture.clone());
            for session_jid in [first, second, unknown] {
                session(
                    &stage,
                    &delivery,
                    SessionChange {
                        session: session_jid.resolve(&arena)?,
                        event: SessionEvent::Bound,
                    },
                )
                .await;
            }
            drop(subscriber);
            capture.assert_one(FailureKind::Delivery, "session_observer");
            assert_eq!(
                *calls.lock(),
                [
                    ("z-first", "alice@localhost/a".into()),
                    ("a-second", "alice@localhost/a".into()),
                    ("a-second", "bob@other.localhost/b".into()),
                ]
            );
            router.shutdown().await?;
            Ok(())
        })
    }
}
