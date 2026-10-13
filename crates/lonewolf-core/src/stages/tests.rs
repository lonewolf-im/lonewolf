// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::num::NonZeroUsize;
use std::time::Duration;

use compio::runtime::Runtime;
use lonewolf_storage::RedbStorage;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::{ParserConfig, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::{MessageType, StanzaErrorCondition};
use parking_lot::Mutex as PlMutex;

use super::{DeliveryOutcome, deliver};
use crate::config::Config;
use crate::delivery::{WorkGroup, WorkHandle};
use crate::hosts::Hosts;
use crate::router::local::LocalRouter;
use crate::router::{RoutedStanza, Router, RouterHandle};
use crate::stages::Stage;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct Fixture {
    _directory: tempfile::TempDir,
    storage: RedbStorage,
    router: Router<GlobalChunkAllocator>,
    handle: RouterHandle<GlobalChunkAllocator>,
    allocator: GlobalChunkAllocator,
    work: WorkHandle,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
        let config = Config::default();
        let hosts = Hosts::new(&config.hosts, None)?;
        let router = Router::new(hosts, LocalRouter::new(GlobalChunkAllocator));
        let handle = router.handle();
        Ok(Self {
            _directory: directory,
            storage,
            router,
            handle,
            allocator: GlobalChunkAllocator,
            work: WorkGroup::new().handle(),
        })
    }

    fn stage(&self) -> Stage<'_, GlobalChunkAllocator> {
        Stage {
            router: &self.handle,
            storage: &self.storage,
            allocator: &self.allocator,
            work: &self.work,
        }
    }
}

fn account(value: &str) -> TestResult<AccountKey> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let jid = Jid::parse_in(value, &mut arena)?;
    Ok(AccountKey::try_from(jid.resolve(&arena)?)?)
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
fn deliver_routes_a_chat_message_to_a_bound_resource() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new()?;
        let recipient = account("bob@localhost")?;
        let registration = fixture
            .handle
            .register(&recipient, Some("phone"), NonZeroUsize::MIN)
            .await?;
        let stanza = parsed(
            "<message from='alice@localhost/laptop' to='bob@localhost/phone' type='chat' id='routed'><body>Hello</body></message>",
        )
        .await?;
        let mut expected = String::new();
        stanza.resolve()?.write_xml(&mut expected)?;

        let outcome = deliver(&fixture.stage(), stanza, MessageType::Chat).await;

        assert!(matches!(outcome, Ok(DeliveryOutcome::Routed)));
        let delivered = registration.recv().await.ok_or("missing routed message")?;
        let mut actual = String::new();
        delivered.stanza.resolve()?.write_xml(&mut actual)?;
        assert_eq!(actual, expected);
        drop(registration);
        fixture.router.shutdown().await?;
        Ok(())
    }))?
}

#[test]
fn deliver_rejects_a_bare_groupchat_message() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new()?;
        let stanza =
            parsed("<message from='alice@localhost/laptop' to='bob@localhost' type='groupchat'/>")
                .await?;

        let outcome = deliver(&fixture.stage(), stanza, MessageType::Groupchat).await;

        assert!(matches!(
            outcome,
            Ok(DeliveryOutcome::Rejected {
                condition: StanzaErrorCondition::ServiceUnavailable,
                ..
            })
        ));
        fixture.router.shutdown().await?;
        Ok(())
    }))?
}

#[test]
fn deliver_discards_an_error_message_to_an_absent_account() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new()?;
        let stanza = parsed(
            "<message from='alice@localhost/laptop' to='absent@localhost/phone' type='error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>",
        )
        .await?;

        let outcome = deliver(&fixture.stage(), stanza, MessageType::Error).await;

        assert!(matches!(outcome, Ok(DeliveryOutcome::Discarded)));
        fixture.router.shutdown().await?;
        Ok(())
    }))?
}

#[test]
fn deliver_rejects_a_chat_message_without_an_offline_handler() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new()?;
        let recipient = account("bob@localhost")?;
        let registration = fixture
            .handle
            .register(&recipient, Some("phone"), NonZeroUsize::MIN)
            .await?;
        let stanza =
            parsed("<message from='alice@localhost/laptop' to='bob@localhost' type='chat'/>")
                .await?;

        let outcome = deliver(&fixture.stage(), stanza, MessageType::Chat).await;

        assert!(matches!(
            outcome,
            Ok(DeliveryOutcome::Rejected {
                condition: StanzaErrorCondition::ServiceUnavailable,
                ..
            })
        ));
        assert!(registration.take_queued().is_empty());
        drop(registration);
        fixture.router.shutdown().await?;
        Ok(())
    }))?
}

#[test]
fn evaluate_allows_without_policies() -> TestResult {
    Runtime::new()?.block_on(async {
        use crate::stages::policy::{Check, evaluate};
        use lonewolf_extension::policy::{Direction, Verdict};
        use lonewolf_xmpp::stanza::StanzaType;

        let fixture = Fixture::new()?;
        let sender = account("alice@localhost")?;
        let recipient = account("bob@other.localhost")?;
        let stanza = parsed(
            "<message from='alice@localhost/desktop' to='bob@other.localhost/phone' type='chat'/>",
        )
        .await?;
        let view = stanza.resolve()?;
        let checks = [
            Check {
                account: &sender,
                direction: Direction::Outbound,
                peer: view.to()?.ok_or("missing to")?,
            },
            Check {
                account: &recipient,
                direction: Direction::Inbound,
                peer: view.from()?.ok_or("missing from")?,
            },
        ];
        assert_eq!(
            evaluate(
                &fixture.stage(),
                StanzaType::Message(MessageType::Chat),
                &checks
            )
            .await
            .map_err(|_| "policy evaluation failed")?,
            Verdict::Allow
        );
        assert_eq!(
            evaluate(
                &fixture.stage(),
                StanzaType::Message(MessageType::Chat),
                &[]
            )
            .await
            .map_err(|_| "policy evaluation failed")?,
            Verdict::Allow
        );
        fixture.router.shutdown().await?;
        Ok(())
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PolicyCall {
    extension: &'static str,
    account: String,
    direction: lonewolf_extension::policy::Direction,
    snapshot: usize,
}

struct RecordingPolicy {
    name: &'static str,
    verdict: lonewolf_extension::policy::Verdict,
    fail: bool,
    calls: std::sync::Arc<PlMutex<Vec<PolicyCall>>>,
}

impl lonewolf_extension::Extension<GlobalChunkAllocator, RedbStorage> for RecordingPolicy {
    fn name(&self) -> &'static str {
        self.name
    }

    fn register(
        self: std::sync::Arc<Self>,
        _: &str,
        slots: &mut lonewolf_extension::Slots<'_, GlobalChunkAllocator, RedbStorage>,
    ) -> Result<(), lonewolf_extension::RegistrationError> {
        slots.policy(self);
        Ok(())
    }
}

impl lonewolf_extension::policy::PolicyHandler<RedbStorage> for RecordingPolicy {
    fn check<'a>(
        &'a self,
        request: lonewolf_extension::policy::PolicyRequest<'a>,
        transaction: &'a lonewolf_storage::RedbRead,
    ) -> lonewolf_extension::policy::PolicyFuture<'a> {
        Box::pin(async move {
            self.calls.lock().push(PolicyCall {
                extension: self.name,
                account: request.account.as_str().into(),
                direction: request.direction,
                snapshot: std::ptr::from_ref(transaction) as usize,
            });
            if self.fail {
                Err(lonewolf_extension::delivery::HandlerError::Internal {
                    condition: StanzaErrorCondition::InternalServerError,
                    failure: lonewolf_extension::delivery::Failure {
                        kind: lonewolf_extension::delivery::FailureKind::Delivery,
                        operation: "test_policy",
                    },
                })
            } else {
                Ok(self.verdict)
            }
        })
    }
}

#[test]
fn evaluate_keeps_registration_and_check_order_on_one_snapshot() -> TestResult {
    Runtime::new()?.block_on(async {
        use crate::stages::policy::{Check, evaluate};
        use lonewolf_extension::Extensions;
        use lonewolf_extension::policy::{Direction, Verdict};
        use lonewolf_xmpp::stanza::ApplicationCondition;
        use std::collections::BTreeMap;
        use std::sync::Arc;

        let mut fixture = Fixture::new()?;
        let calls = Arc::new(PlMutex::new(Vec::new()));
        let first = Verdict::Reject {
            condition: StanzaErrorCondition::NotAcceptable,
            application: Some(ApplicationCondition {
                name: "blocked",
                namespace: "urn:test:policy",
            }),
        };
        let mut extensions = Extensions::default();
        for (name, verdict) in [
            ("z-first", first),
            (
                "a-second",
                Verdict::Reject {
                    condition: StanzaErrorCondition::ServiceUnavailable,
                    application: None,
                },
            ),
        ] {
            extensions.register(Arc::new(RecordingPolicy {
                name,
                verdict,
                fail: false,
                calls: Arc::clone(&calls),
            }))?;
        }
        fixture.router = fixture.router.with_extensions(BTreeMap::from([
            (
                "localhost".into(),
                extensions.enable_host("localhost", ["z-first", "a-second"])?,
            ),
            (
                "other.localhost".into(),
                extensions.enable_host("other.localhost", ["a-second", "z-first"])?,
            ),
        ]));
        fixture.handle = fixture.router.handle();
        let sender = account("alice@localhost")?;
        let recipient = account("bob@other.localhost")?;
        let stanza = parsed(
            "<message from='alice@localhost/desktop' to='bob@other.localhost/phone' type='chat'/>",
        )
        .await?;
        let view = stanza.resolve()?;
        let checks = [
            Check {
                account: &sender,
                direction: Direction::Outbound,
                peer: view.to()?.ok_or("missing to")?,
            },
            Check {
                account: &recipient,
                direction: Direction::Inbound,
                peer: view.from()?.ok_or("missing from")?,
            },
        ];

        assert_eq!(
            evaluate(&fixture.stage(), view.stanza_type(), &checks)
                .await
                .map_err(|_| "policy failed")?,
            first
        );
        {
            let actual = calls.lock();
            assert_eq!(actual.len(), 4);
            let snapshot = actual[0].snapshot;
            assert_eq!(
                &*actual,
                &[
                    PolicyCall {
                        extension: "z-first",
                        account: "alice@localhost".into(),
                        direction: Direction::Outbound,
                        snapshot
                    },
                    PolicyCall {
                        extension: "a-second",
                        account: "alice@localhost".into(),
                        direction: Direction::Outbound,
                        snapshot
                    },
                    PolicyCall {
                        extension: "a-second",
                        account: "bob@other.localhost".into(),
                        direction: Direction::Inbound,
                        snapshot
                    },
                    PolicyCall {
                        extension: "z-first",
                        account: "bob@other.localhost".into(),
                        direction: Direction::Inbound,
                        snapshot
                    },
                ]
            );
        }
        fixture.router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn evaluate_fails_closed_and_stops_handlers_and_checks_after_drop() -> TestResult {
    Runtime::new()?.block_on(async {
        use crate::stages::policy::{Check, evaluate};
        use lonewolf_extension::Extensions;
        use lonewolf_extension::policy::{Direction, Verdict};
        use lonewolf_xmpp::stanza::{IqType, StanzaType};
        use std::collections::BTreeMap;
        use std::sync::Arc;

        let mut fixture = Fixture::new()?;
        let calls = Arc::new(PlMutex::new(Vec::new()));
        let mut extensions = Extensions::default();
        for (name, verdict, fail) in [
            ("broken", Verdict::Allow, true),
            ("drop", Verdict::Drop, false),
            ("skipped", Verdict::Allow, false),
        ] {
            extensions.register(Arc::new(RecordingPolicy {
                name,
                verdict,
                fail,
                calls: Arc::clone(&calls),
            }))?;
        }
        fixture.router = fixture.router.with_extensions(BTreeMap::from([(
            "localhost".into(),
            extensions.enable_host("localhost", ["broken", "drop", "skipped"])?,
        )]));
        fixture.handle = fixture.router.handle();
        let sender = account("alice@localhost")?;
        let recipient = account("bob@localhost")?;
        let stanza = parsed(
            "<message from='alice@localhost/desktop' to='bob@localhost/phone' type='chat'/>",
        )
        .await?;
        let view = stanza.resolve()?;
        let checks = [
            Check {
                account: &sender,
                direction: Direction::Outbound,
                peer: view.to()?.ok_or("missing to")?,
            },
            Check {
                account: &recipient,
                direction: Direction::Inbound,
                peer: view.from()?.ok_or("missing from")?,
            },
        ];
        assert_eq!(
            evaluate(&fixture.stage(), view.stanza_type(), &checks)
                .await
                .map_err(|_| "policy failed")?,
            Verdict::Drop
        );
        assert_eq!(
            calls
                .lock()
                .iter()
                .map(|call| call.extension)
                .collect::<Vec<_>>(),
            ["broken", "drop"]
        );

        fixture.router = fixture.router.with_extensions(BTreeMap::from([(
            "localhost".into(),
            extensions.enable_host("localhost", ["broken"])?,
        )]));
        fixture.handle = fixture.router.handle();
        assert_eq!(
            evaluate(&fixture.stage(), view.stanza_type(), &checks[..1])
                .await
                .map_err(|_| "policy failed")?,
            Verdict::Reject {
                condition: StanzaErrorCondition::InternalServerError,
                application: None
            }
        );
        assert_eq!(
            evaluate(
                &fixture.stage(),
                StanzaType::Iq(IqType::Result),
                &checks[..1]
            )
            .await
            .map_err(|_| "policy failed")?,
            Verdict::Drop
        );
        fixture.router.shutdown().await?;
        Ok(())
    })
}

#[derive(Clone)]
struct UnavailableAllocator;

// This allocator never returns a chunk.
unsafe impl lonewolf_util::arena::ChunkAllocator for UnavailableAllocator {
    fn allocate(
        &self,
        _: std::alloc::Layout,
    ) -> Result<lonewolf_util::arena::Chunk, lonewolf_util::arena::AllocationError> {
        Err(lonewolf_util::arena::AllocationError::Exhausted)
    }

    unsafe fn deallocate(&self, _: lonewolf_util::arena::Chunk) {
        panic!("unavailable allocator has no live chunks");
    }
}

#[test]
fn filter_audience_without_policies_does_not_allocate_an_arena() -> TestResult {
    Runtime::new()?.block_on(async {
        use lonewolf_extension::presence::PresenceAudience;
        use lonewolf_storage::Storage;
        use lonewolf_storage::roster::{PendingSubscription, RosterJid};
        use lonewolf_xmpp::stanza::{PresenceType, StanzaType};

        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
        let config = Config::default();
        let router = Router::new(
            Hosts::new(&config.hosts, None)?,
            LocalRouter::new(UnavailableAllocator),
        );
        let handle = router.handle();
        let owner = account("alice@localhost")?;
        let subscriber = account("bob@localhost")?;
        let contact = account("carol@other.localhost")?;
        let pending = PendingSubscription {
            sender: RosterJid::from(&subscriber),
            stanza: Box::from([]),
        };
        let mut audience = PresenceAudience {
            subscribers: vec![RosterJid::from(&subscriber)],
            contacts: vec![contact.clone()],
            pending: vec![pending.clone()],
        };
        let mut arena = Arena::try_new(Default::default())?;
        let sender = Jid::parse_in("alice@localhost/res", &mut arena)?;
        let transaction = storage.begin_read().await?;
        crate::stages::policy::filter_audience(
            &handle,
            &transaction,
            &UnavailableAllocator,
            &owner,
            sender.resolve(&arena)?,
            StanzaType::Presence(PresenceType::Available),
            &mut audience,
        )
        .await
        .map_err(|_| "audience filtering attempted allocation")?;
        assert_eq!(audience.subscribers, [RosterJid::from(&subscriber)]);
        assert_eq!(audience.contacts, [contact]);
        assert_eq!(audience.pending, [pending]);
        router.shutdown().await?;
        Ok(())
    })
}
