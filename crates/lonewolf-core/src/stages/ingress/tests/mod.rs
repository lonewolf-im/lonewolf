// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::error::Error;
use std::num::NonZeroUsize;
use std::sync::Arc;

use compio::runtime::Runtime;
use futures_util::FutureExt;
use lonewolf_extension::delivery::{Delivery, DeliveryFuture, SessionId};
use lonewolf_extension::observer::{MessageEvent, MessageObserver, MessageOutcome, MessageRole};
use lonewolf_extension::policy::{Direction, PolicyFuture, PolicyHandler, PolicyRequest, Verdict};
use lonewolf_extension::{Extension, Extensions, RegistrationError, Slots};
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::{RedbRead, RedbStorage, Storage};
use lonewolf_util::arena::{Arena, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::{
    MessageType, RoutedStanza, Stanza, StanzaKind, StanzaNamespace, StanzaType,
};
use parking_lot::Mutex as PlMutex;

use super::Origin;
use super::checks::{Snapshot, check, observe_message, parties, policy_applies};
use crate::config::Config;
use crate::delivery::{WorkGroup, WorkHandle};
use crate::hosts::Hosts;
use crate::router::local::LocalRouter;
use crate::router::{Admitted, Router, RouterHandle};
use crate::stages::Stage;
use crate::stages::message::DeliveryOutcome;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[derive(Debug, PartialEq)]
struct PolicyCall {
    account: String,
    direction: Direction,
    peer: String,
    kind: StanzaType,
}

#[derive(Debug, PartialEq)]
struct Observation {
    account: String,
    role: MessageRole,
    outcome: MessageOutcome,
    holders: Vec<SessionId>,
}

#[derive(Default)]
struct Recorder {
    policies: PlMutex<Vec<PolicyCall>>,
    observations: PlMutex<Vec<Observation>>,
}

impl Extension<GlobalChunkAllocator, RedbStorage> for Recorder {
    fn name(&self) -> &'static str {
        "recorder"
    }

    fn register(
        self: Arc<Self>,
        _: &str,
        slots: &mut Slots<'_, GlobalChunkAllocator, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.iq_destination(
            lonewolf_extension::iq::IqRequestKey {
                kind: lonewolf_extension::iq::IqRequestType::Set,
                namespace: "urn:test:destination",
                name: "guarded",
            },
            lonewolf_extension::iq::IqDestinationRule::SenderBare,
        )?;
        slots.policy(self.clone());
        slots.message_observer(self);
        Ok(())
    }
}

impl PolicyHandler<RedbStorage> for Recorder {
    fn check<'a>(&'a self, request: PolicyRequest<'a>, _: &'a RedbRead) -> PolicyFuture<'a> {
        Box::pin(async move {
            self.policies.lock().push(PolicyCall {
                account: request.account.as_str().into(),
                direction: request.direction,
                peer: request.peer.as_str().into(),
                kind: request.kind,
            });
            Ok(Verdict::Allow)
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
        Box::pin(async move {
            self.observations.lock().push(Observation {
                account: event.account.as_str().into(),
                role: event.role,
                outcome: event.outcome,
                holders: event.holders.to_vec(),
            });
            Ok(())
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
    fn new(enabled: bool) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
        let recorder = Arc::new(Recorder::default());
        let mut extensions = Extensions::default();
        extensions.register(recorder.clone())?;
        let router = Router::new(
            Hosts::new(&Config::default().hosts, None)?,
            LocalRouter::new(GlobalChunkAllocator),
        )
        .with_extensions(BTreeMap::from([(
            "localhost".into(),
            extensions.enable_host("localhost", enabled.then_some("recorder"))?,
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

fn account(text: &str) -> TestResult<AccountKey> {
    let mut arena = Arena::try_new(Default::default())?;
    let jid = Jid::parse_in(text, &mut arena)?;
    Ok(AccountKey::try_from(jid.resolve(&arena)?)?)
}

fn stanza(from: &str, to: &str) -> TestResult<RoutedStanza<GlobalChunkAllocator>> {
    let mut arena = Arena::try_new(Default::default())?;
    let from = Jid::parse_in(from, &mut arena)?;
    let to = Jid::parse_in(to, &mut arena)?;
    let stanza = Stanza::builder_in(
        StanzaType::Message(MessageType::Chat),
        StanzaNamespace::Client,
        &mut arena,
    )
    .from(Some(from))?
    .to(Some(to))?
    .build()?;
    Ok(RoutedStanza::from_parts(stanza, arena))
}

#[test]
fn parties_builds_no_account_key_without_handlers() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(false)?;
        let origin = Origin::Remote {
            local: "localhost",
            remote: "remote.test",
        };
        for (to, local_recipient) in [
            ("bob@localhost", true),
            ("bob@localhost/phone", true),
            ("localhost", false),
            ("bob@remote.test", false),
        ] {
            let routed = stanza("alice@remote.test/phone", to)?;
            let view = routed.resolve()?;
            let to = view.to()?.ok_or("recipient")?;
            let parties = parties(&fixture.handle, &origin, to, StanzaKind::Message)
                .map_err(|_| "parties failed")?;
            assert_eq!(parties.local_recipient, local_recipient);
            assert!(!parties.same_account);
            assert!(parties.recipient.is_none());
            assert!(!policy_applies(&fixture.handle, &origin, to, &parties));
        }
        fixture.router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn check_skips_storage_within_one_account() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(true)?;
        let owner = account("alice@localhost")?;
        let session = fixture
            .handle
            .register(&owner, Some("phone"), NonZeroUsize::MIN)
            .await?;
        let origin = Origin::Session(&session);
        assert!(origin.detaches());
        let routed = stanza("alice@localhost/phone", "alice@localhost/tablet")?;
        let view = routed.resolve()?;
        let parties = parties(
            &fixture.handle,
            &origin,
            view.to()?.ok_or("recipient")?,
            StanzaKind::Message,
        )
        .map_err(|_| "parties failed")?;
        assert!(parties.same_account);
        let result = check(&fixture.stage(), &origin, &view, &parties, Snapshot::Fresh)
            .now_or_never()
            .ok_or("policy waited for storage")?
            .map_err(|_| "policy failed")?;
        assert_eq!(result, Verdict::Allow);
        assert!(fixture.recorder.policies.lock().is_empty());
        drop(session);
        fixture.router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn check_orders_outbound_before_inbound() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(true)?;
        let owner = account("alice@localhost")?;
        let session = fixture
            .handle
            .register(&owner, Some("phone"), NonZeroUsize::MIN)
            .await?;
        let origin = Origin::Session(&session);
        let routed = stanza("alice@localhost/phone", "bob@localhost")?;
        let view = routed.resolve()?;
        let parties = parties(
            &fixture.handle,
            &origin,
            view.to()?.ok_or("recipient")?,
            StanzaKind::Message,
        )
        .map_err(|_| "parties failed")?;
        let transaction = fixture.storage.begin_read().await?;
        for snapshot in [Snapshot::Fresh, Snapshot::Ordered(&transaction)] {
            assert_eq!(
                check(&fixture.stage(), &origin, &view, &parties, snapshot)
                    .await
                    .map_err(|_| "policy failed")?,
                Verdict::Allow
            );
            assert_eq!(
                *fixture.recorder.policies.lock(),
                [
                    PolicyCall {
                        account: "alice@localhost".into(),
                        direction: Direction::Outbound,
                        peer: "bob@localhost".into(),
                        kind: view.stanza_type()
                    },
                    PolicyCall {
                        account: "bob@localhost".into(),
                        direction: Direction::Inbound,
                        peer: "alice@localhost/phone".into(),
                        kind: view.stanza_type()
                    },
                ]
            );
            fixture.recorder.policies.lock().clear();
        }
        drop(transaction);
        drop(session);
        fixture.router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn observe_message_holders_follow_origin_and_account() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(true)?;
        let owner = account("alice@localhost")?;
        let session = fixture
            .handle
            .register(&owner, Some("phone"), NonZeroUsize::MIN)
            .await?;
        let target = account("bob@localhost")?;
        let recipient = fixture
            .handle
            .register(&target, Some("tablet"), NonZeroUsize::MIN)
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
                Origin::Session(_) => "alice@localhost/phone",
                Origin::Remote { .. } => "alice@remote.test",
                Origin::Service { .. } => "service.test",
            };
            assert_eq!(origin.detaches(), origin.session().is_some());
            for same_account in [false, true] {
                if same_account && origin.session().is_none() {
                    continue;
                }
                let to = if same_account {
                    "alice@localhost"
                } else {
                    "bob@localhost"
                };
                let routed = stanza(from, to)?;
                let view = routed.resolve()?;
                let parties = parties(
                    &fixture.handle,
                    &origin,
                    view.to()?.ok_or("recipient")?,
                    StanzaKind::Message,
                )
                .map_err(|_| "parties failed")?;
                for outcome in [
                    DeliveryOutcome::Routed {
                        admitted: Admitted::One(recipient.session_id()),
                    },
                    DeliveryOutcome::Stored {
                        admitted: Admitted::One(recipient.session_id()),
                    },
                    DeliveryOutcome::Discarded,
                    DeliveryOutcome::Rejected {
                        stanza: routed.clone(),
                        condition: lonewolf_xmpp::stanza::StanzaErrorCondition::ServiceUnavailable,
                        text: lonewolf_xmpp::stanza::StanzaErrorCondition::ServiceUnavailable
                            .default_text(),
                    },
                ] {
                    observe_message(
                        &fixture.stage(),
                        &origin,
                        &parties,
                        &routed,
                        &outcome,
                        (None, None),
                        None,
                    )
                    .await;
                    let delivered = matches!(
                        outcome,
                        DeliveryOutcome::Routed { .. } | DeliveryOutcome::Stored { .. }
                    );
                    let mut holders = Vec::new();
                    if same_account {
                        holders.push(session.session_id());
                    }
                    if delivered {
                        holders.push(recipient.session_id());
                    }
                    let mut expected = Vec::new();
                    if origin.session().is_some() {
                        expected.push(Observation {
                            account: owner.as_str().into(),
                            role: MessageRole::Sent,
                            outcome: MessageOutcome::from(&outcome),
                            holders: if same_account {
                                holders.clone()
                            } else {
                                vec![session.session_id()]
                            },
                        });
                    }
                    if delivered {
                        expected.push(Observation {
                            account: to.into(),
                            role: MessageRole::Received,
                            outcome: MessageOutcome::from(&outcome),
                            holders,
                        });
                    }
                    assert_eq!(*fixture.recorder.observations.lock(), expected);
                    fixture.recorder.observations.lock().clear();
                }
            }
        }
        drop(recipient);
        drop(session);
        fixture.router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn destination_error_uses_authenticated_account_before_stamping() -> TestResult {
    let fixture = Fixture::new(true)?;
    let owner = account("alice@localhost")?;
    for (sender, to, rejected) in [
        (Some(&owner), Some("alice@localhost"), false),
        (Some(&owner), None, false),
        (Some(&owner), Some("alice@localhost/phone"), true),
        (Some(&owner), Some("bob@localhost"), true),
        (None, Some("alice@localhost"), true),
    ] {
        let mut arena = Arena::try_new(Default::default())?;
        let from = Jid::parse_in("bob@localhost", &mut arena)?;
        let to = to.map(|to| Jid::parse_in(to, &mut arena)).transpose()?;
        let child = lonewolf_xmpp::stanza::Element::builder_in(
            "guarded",
            "urn:test:destination",
            &mut arena,
        )?
        .build()?;
        let request = Stanza::builder_in(
            StanzaType::Iq(lonewolf_xmpp::stanza::IqType::Set),
            StanzaNamespace::Client,
            &mut arena,
        )
        .id(Some("guarded"))?
        .from(Some(from))?
        .to(to)?
        .child(child)?
        .build()?;
        let result = crate::stages::iq::destination_error(
            &fixture.handle,
            sender,
            &request.resolve(&arena)?,
        )
        .map_err(|_| "destination failed")?;
        assert_eq!(result.is_some(), rejected);
    }
    let mut arena = Arena::try_new(Default::default())?;
    let child =
        lonewolf_xmpp::stanza::Element::builder_in("guarded", "urn:test:destination", &mut arena)?
            .build()?;
    let request = Stanza::builder_in(
        StanzaType::Iq(lonewolf_xmpp::stanza::IqType::Set),
        StanzaNamespace::Client,
        &mut arena,
    )
    .id(Some("guarded"))?
    .child(child)?
    .build()?;
    assert!(
        crate::stages::iq::destination_error(&fixture.handle, None, &request.resolve(&arena)?)
            .is_err()
    );
    Runtime::new()?.block_on(fixture.router.shutdown())?;
    Ok(())
}
