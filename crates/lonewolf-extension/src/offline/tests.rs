// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::error::Error;
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_executor::block_on;
use lonewolf_auth::scram::{
    SCRAM_POLICY_ITERATIONS, ScramCredentials, ScramSha1Verifier, ScramVerifier,
};
use lonewolf_storage::account::{AccountKey, AccountWrites, NewAccount};
use lonewolf_storage::offline::{OfflineReads, OfflineSequence};
use lonewolf_storage::{RedbStorage, Storage, WriteTransaction};
use lonewolf_util::arena::{Arena, ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::{ParserConfig, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::{RoutedStanza, StanzaErrorCondition};

use super::{Offline, OfflineLimits};
use crate::account::AccountHandler;
use crate::delivery::{HandlerError, HostLookup};
use crate::message::{Backlog, MessageHandler, StoreOutcome, UndeliverableMessage};
use crate::presence::PresenceRequestType;
use crate::{Extension, Extensions};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
type TestHandler = dyn MessageHandler<GlobalChunkAllocator, RedbStorage>;
type TestExtension = dyn Extension<GlobalChunkAllocator, RedbStorage>;
type TestAccountHandler = dyn AccountHandler<GlobalChunkAllocator, RedbStorage>;

const RECEIVED_SECONDS: u64 = 1_700_000_000;
const MESSAGE: &str =
    "<message from='alice@example.org/desk' to='bob@example.com'><body>hello</body></message>";

struct TestOffline {
    storage: RedbStorage,
    offline: Offline,
    _directory: tempfile::TempDir,
}

impl HostLookup for TestOffline {
    fn is_local_host(&self, domain: &str) -> bool {
        matches!(domain, "example.com" | "example.org")
    }
}

fn key(value: &str) -> TestResult<AccountKey> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let jid = Jid::parse_in(value, &mut arena)?;
    Ok(AccountKey::try_from(jid.resolve(&arena)?)?)
}

async fn stanza(xml: &str) -> TestResult<RoutedStanza<GlobalChunkAllocator>> {
    let input = format!(
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'>{xml}</stream:stream>"
    );
    let mut parser = XmppParser::new(
        input.as_bytes(),
        ParserConfig {
            max_stanza_bytes: NonZeroUsize::new(262_144).ok_or("invalid stanza limit")?,
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
        _ => Err("expected stanza".into()),
    }
}

fn received_at() -> SystemTime {
    UNIX_EPOCH + Duration::new(RECEIVED_SECONDS, 987_654_321)
}

impl TestOffline {
    async fn new(limits: BTreeMap<Box<str>, OfflineLimits>, owners: &[&str]) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
        let mut transaction = storage.begin_write().await?;
        for owner in owners {
            transaction
                .create_account(NewAccount {
                    key: key(owner)?,
                    credentials: ScramCredentials::new(ScramVerifier::Sha1(
                        ScramSha1Verifier::new(
                            [11; 16],
                            SCRAM_POLICY_ITERATIONS,
                            [12; 20],
                            [13; 20],
                        ),
                    )),
                })
                .await?;
        }
        transaction.commit().await?;
        Ok(Self {
            storage,
            offline: Offline::new(limits),
            _directory: directory,
        })
    }

    async fn store_at(
        &self,
        recipient: &AccountKey,
        xml: &str,
        received_at: SystemTime,
    ) -> TestResult<Result<StoreOutcome, HandlerError>> {
        let stanza = stanza(xml).await?;
        let mut scratch = Arena::try_new(ArenaConfig::default())?;
        let mut transaction = self.storage.begin_write().await?;
        let handler: &TestHandler = &self.offline;
        let result = handler
            .store(
                UndeliverableMessage {
                    recipient,
                    stanza: &stanza,
                    received_at,
                },
                &mut transaction,
                &mut scratch,
            )
            .await;
        if matches!(result, Ok(StoreOutcome::Stored(_))) {
            transaction.commit().await?;
        }
        Ok(result)
    }

    async fn store(&self, recipient: &AccountKey, xml: &str) -> TestResult<OfflineSequence> {
        match self.store_at(recipient, xml, received_at()).await? {
            Ok(StoreOutcome::Stored(sequence)) => Ok(sequence),
            outcome => Err(format!("expected stored message, got {outcome:?}").into()),
        }
    }

    async fn backlog(&self, owner: &AccountKey) -> TestResult<Option<Backlog>> {
        let transaction = self.storage.begin_read().await?;
        let handler: &TestHandler = &self.offline;
        handler
            .backlog(owner, &transaction)
            .await
            .map_err(|error| format!("{error:?}").into())
    }
}

#[test]
fn normal_untyped_and_chat_messages_are_stored_in_order() -> TestResult {
    block_on(async {
        let test = TestOffline::new(BTreeMap::new(), &["bob@example.com"]).await?;
        let owner = key("bob@example.com")?;
        for (index, xml) in [
            MESSAGE,
            "<message type='normal'><body>normal</body></message>",
            "<message type='chat'><body>chat</body></message>",
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(test.store(&owner, xml).await?.get(), index as u64 + 1);
        }
        let backlog = test.backlog(&owner).await?.ok_or("missing backlog")?;
        assert_eq!(backlog.messages.len(), 3);
        assert_eq!(backlog.through.get(), 3);
        for (index, stored) in backlog.messages.iter().enumerate() {
            assert_eq!(stored.sequence.get(), index as u64 + 1);
            assert_eq!(stored.stored_at, RECEIVED_SECONDS);
            assert!(std::str::from_utf8(&stored.stanza)?.contains("<body>"));
        }
        Ok(())
    })
}

#[test]
fn standalone_chat_states_with_optional_threads_are_discarded() -> TestResult {
    block_on(async {
        let test = TestOffline::new(BTreeMap::new(), &["bob@example.com"]).await?;
        let owner = key("bob@example.com")?;
        for children in [
            "<active xmlns='http://jabber.org/protocol/chatstates'/>",
            "<composing xmlns='http://jabber.org/protocol/chatstates'/><thread>discussion</thread>",
            "<thread>discussion</thread><paused xmlns='http://jabber.org/protocol/chatstates'/>",
        ] {
            assert_eq!(
                test.store_at(
                    &owner,
                    &format!("<message>{children}</message>"),
                    received_at()
                )
                .await?
                .map_err(|error| format!("{error:?}"))?,
                StoreOutcome::Discarded
            );
        }
        assert!(test.backlog(&owner).await?.is_none());
        Ok(())
    })
}

#[test]
fn chat_states_with_message_payloads_are_stored() -> TestResult {
    block_on(async {
        let test = TestOffline::new(BTreeMap::new(), &["bob@example.com"]).await?;
        let owner = key("bob@example.com")?;
        for payload in [
            "<body>hello</body>",
            "<received xmlns='urn:xmpp:receipts' id='receipt'/>",
            "<x xmlns='urn:test:payload'/>",
            "<body xmlns='urn:test:payload'>foreign body</body>",
            "<subject>topic</subject>",
        ] {
            test.store(&owner, &format!("<message><active xmlns='http://jabber.org/protocol/chatstates'/>{payload}</message>")).await?;
        }
        assert_eq!(
            test.backlog(&owner)
                .await?
                .ok_or("missing backlog")?
                .messages
                .len(),
            5
        );
        Ok(())
    })
}

#[test]
fn receipts_other_payloads_empty_messages_and_thread_only_messages_are_stored() -> TestResult {
    block_on(async {
        let test = TestOffline::new(BTreeMap::new(), &["bob@example.com"]).await?;
        let owner = key("bob@example.com")?;
        for xml in [
            "<message><received xmlns='urn:xmpp:receipts' id='receipt'/></message>",
            "<message><x xmlns='urn:test:payload'/></message>",
            "<message/>",
            "<message><thread>discussion</thread></message>",
        ] {
            test.store(&owner, xml).await?;
        }
        assert_eq!(
            test.backlog(&owner)
                .await?
                .ok_or("missing backlog")?
                .messages
                .len(),
            4
        );
        Ok(())
    })
}

#[test]
fn delay_stamp_uses_recipient_domain_and_utc_receive_time_without_fractions() -> TestResult {
    block_on(async {
        let test = TestOffline::new(BTreeMap::new(), &["bob@example.com"]).await?;
        let owner = key("bob@example.com")?;
        test.store(&owner, MESSAGE).await?;
        let backlog = test.backlog(&owner).await?.ok_or("missing backlog")?;
        let stored = &backlog.messages[0];
        assert_eq!(stored.stored_at, RECEIVED_SECONDS);
        let parsed = stanza(std::str::from_utf8(&stored.stanza)?).await?;
        let view = parsed.resolve()?;
        let delay = view
            .child("delay", "urn:xmpp:delay")?
            .ok_or("missing delay")?;
        assert_eq!(delay.attribute("from", "")?, Some("example.com"));
        assert_eq!(delay.attribute("stamp", "")?, Some("2023-11-14T22:13:20Z"));
        assert_eq!(
            view.from()?.ok_or("missing sender")?.domainpart(),
            "example.org"
        );
        Ok(())
    })
}

#[test]
fn forged_local_delays_are_removed_and_other_children_keep_their_order() -> TestResult {
    block_on(async {
        let test = TestOffline::new(BTreeMap::new(), &["bob@example.com"]).await?;
        let owner = key("bob@example.com")?;
        test.store(&owner, "<message from='alice@example.org/desk' to='bob@example.com' id='client-id' xml:lang='en' flag='value'><delay xmlns='urn:xmpp:delay' from='example.com' stamp='forged'/><body>Hello &amp; goodbye</body><delay xmlns='urn:xmpp:delay' from='example.org' stamp='foreign'/><delay xmlns='urn:xmpp:delay' stamp='no-from'/><delay xmlns='urn:other' from='example.com'/><delay xmlns='urn:xmpp:delay' from='example.com' stamp='forged-too'/><received xmlns='urn:xmpp:receipts' id='receipt'/></message>").await?;
        let backlog = test.backlog(&owner).await?.ok_or("missing backlog")?;
        let parsed = stanza(std::str::from_utf8(&backlog.messages[0].stanza)?).await?;
        let view = parsed.resolve()?;
        assert_eq!(view.id()?, Some("client-id"));
        assert_eq!(view.lang()?, Some("en"));
        assert_eq!(view.attribute("flag", "")?, Some("value"));
        assert_eq!(
            view.to()?.ok_or("missing recipient")?.domainpart(),
            "example.com"
        );
        let children = view.children()?.collect::<Result<Vec<_>, _>>()?;
        assert_eq!(children.len(), 6);
        assert_eq!(children[0].name(), "body");
        assert_eq!(children[0].text()?, Some("Hello & goodbye"));
        assert_eq!(children[1].attribute("stamp", "")?, Some("foreign"));
        assert_eq!(children[2].attribute("stamp", "")?, Some("no-from"));
        assert_eq!(children[3].namespace(), "urn:other");
        assert_eq!(children[4].namespace(), "urn:xmpp:receipts");
        assert_eq!(
            children[5].attribute("stamp", "")?,
            Some("2023-11-14T22:13:20Z")
        );
        Ok(())
    })
}

#[test]
fn per_host_quota_accepts_the_limit_then_rejects_the_next_message() -> TestResult {
    block_on(async {
        let limits = BTreeMap::from([(
            "example.com".into(),
            OfflineLimits {
                max_messages_per_account: NonZeroU32::new(2).ok_or("invalid limit")?,
            },
        )]);
        let test = TestOffline::new(limits, &["bob@example.com", "carol@example.org"]).await?;
        let owner = key("bob@example.com")?;
        for _ in 0..2 {
            test.store(&owner, MESSAGE).await?;
        }
        assert!(matches!(
            test.store_at(&owner, MESSAGE, received_at()).await?,
            Err(HandlerError::Stanza(
                StanzaErrorCondition::ResourceConstraint
            ))
        ));
        assert_eq!(
            test.backlog(&owner)
                .await?
                .ok_or("missing backlog")?
                .messages
                .len(),
            2
        );
        assert_eq!(
            test.store_at(
                &owner,
                "<message><active xmlns='http://jabber.org/protocol/chatstates'/></message>",
                received_at()
            )
            .await?
            .map_err(|error| format!("{error:?}"))?,
            StoreOutcome::Discarded
        );
        let other = key("carol@example.org")?;
        for _ in 0..3 {
            test.store(&other, MESSAGE).await?;
        }
        assert_eq!(
            test.backlog(&other)
                .await?
                .ok_or("missing backlog")?
                .messages
                .len(),
            3
        );
        assert_eq!(OfflineLimits::default().max_messages_per_account.get(), 100);
        Ok(())
    })
}

#[test]
fn unknown_accounts_receive_service_unavailable_and_keep_no_backlog() -> TestResult {
    block_on(async {
        let test = TestOffline::new(BTreeMap::new(), &[]).await?;
        let owner = key("bob@example.com")?;
        assert!(matches!(
            test.store_at(&owner, MESSAGE, received_at()).await?,
            Err(HandlerError::Stanza(
                StanzaErrorCondition::ServiceUnavailable
            ))
        ));
        assert!(test.backlog(&owner).await?.is_none());
        Ok(())
    })
}

#[test]
fn unsupported_message_types_are_rejected_before_chat_state_filtering() -> TestResult {
    block_on(async {
        let test = TestOffline::new(BTreeMap::new(), &["bob@example.com"]).await?;
        let owner = key("bob@example.com")?;
        for xml in [
            "<message type='headline'><active xmlns='http://jabber.org/protocol/chatstates'/></message>",
            "<message type='groupchat'><body>hello</body></message>",
            "<message type='error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>",
            "<presence/>",
        ] {
            assert!(matches!(
                test.store_at(&owner, xml, received_at()).await?,
                Err(HandlerError::Stanza(
                    StanzaErrorCondition::ServiceUnavailable
                ))
            ));
        }
        assert!(test.backlog(&owner).await?.is_none());
        Ok(())
    })
}

#[test]
fn invalid_receive_times_fail_without_storing_or_allocating_a_sequence() -> TestResult {
    block_on(async {
        let test = TestOffline::new(BTreeMap::new(), &["bob@example.com"]).await?;
        let owner = key("bob@example.com")?;
        for received_at in [
            UNIX_EPOCH - Duration::from_nanos(1),
            UNIX_EPOCH + Duration::from_secs(253_402_300_800),
        ] {
            assert!(matches!(
                test.store_at(&owner, MESSAGE, received_at).await?,
                Err(HandlerError::Stanza(
                    StanzaErrorCondition::InternalServerError
                ))
            ));
        }
        assert!(test.backlog(&owner).await?.is_none());
        assert_eq!(test.store(&owner, MESSAGE).await?.get(), 1);
        Ok(())
    })
}

#[test]
fn acknowledging_backlog_preserves_messages_added_after_the_snapshot() -> TestResult {
    block_on(async {
        let test = TestOffline::new(BTreeMap::new(), &["bob@example.com"]).await?;
        let owner = key("bob@example.com")?;
        test.store(&owner, MESSAGE).await?;
        test.store(&owner, MESSAGE).await?;
        let backlog = test.backlog(&owner).await?.ok_or("missing backlog")?;
        let later = test.store(&owner, MESSAGE).await?;
        let handler: &TestHandler = &test.offline;
        let mut transaction = test.storage.begin_write().await?;
        handler
            .acknowledge(&owner, backlog.through, &mut transaction)
            .await
            .map_err(|error| format!("{error:?}"))?;
        transaction.commit().await?;
        let remaining = test.backlog(&owner).await?.ok_or("missing later message")?;
        assert_eq!(remaining.messages.len(), 1);
        assert_eq!(remaining.through, later);
        assert_eq!(test.store(&owner, MESSAGE).await?.get(), 4);
        Ok(())
    })
}

#[test]
fn acknowledging_one_message_keeps_the_other_sequences() -> TestResult {
    block_on(async {
        let test = TestOffline::new(BTreeMap::new(), &["bob@example.com"]).await?;
        let owner = key("bob@example.com")?;
        let first = test.store(&owner, MESSAGE).await?;
        let second = test.store(&owner, MESSAGE).await?;
        let handler: &TestHandler = &test.offline;
        let mut transaction = test.storage.begin_write().await?;
        handler
            .acknowledge_one(&owner, second, &mut transaction)
            .await
            .map_err(|error| format!("{error:?}"))?;
        transaction.commit().await?;
        let remaining = test.backlog(&owner).await?.ok_or("missing first message")?;
        assert_eq!(remaining.messages.len(), 1);
        assert_eq!(remaining.through, first);
        assert_eq!(test.store(&owner, MESSAGE).await?.get(), 3);
        Ok(())
    })
}

#[test]
fn forgetting_account_clears_messages_and_the_sequence_in_the_deletion_transaction() -> TestResult {
    block_on(async {
        let test =
            TestOffline::new(BTreeMap::new(), &["bob@example.com", "carol@example.org"]).await?;
        let owner = key("bob@example.com")?;
        let other = key("carol@example.org")?;
        test.store(&owner, MESSAGE).await?;
        test.store(&other, MESSAGE).await?;
        let extension: &TestAccountHandler = &test.offline;
        let mut transaction = test.storage.begin_write().await?;
        transaction.delete_account(&owner).await?;
        let effects = extension
            .forget_account(&mut transaction, &owner, &test)
            .await
            .map_err(|error| format!("{error:?}"))?;
        assert!(effects.accounts.is_empty());
        assert_eq!(transaction.offline_count(&owner).await?, 0);
        transaction.commit().await?;
        assert!(test.backlog(&owner).await?.is_none());
        assert_eq!(
            test.backlog(&other)
                .await?
                .ok_or("missing other backlog")?
                .messages
                .len(),
            1
        );
        let mut transaction = test.storage.begin_write().await?;
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
        assert_eq!(test.store(&owner, MESSAGE).await?.get(), 1);
        Ok(())
    })
}

#[test]
fn hosts_without_configured_limits_enforce_the_default_quota() -> TestResult {
    block_on(async {
        let test = TestOffline::new(BTreeMap::new(), &["bob@example.com"]).await?;
        let owner = key("bob@example.com")?;
        for _ in 0..100 {
            test.store(&owner, MESSAGE).await?;
        }
        assert!(matches!(
            test.store_at(&owner, MESSAGE, received_at()).await?,
            Err(HandlerError::Stanza(
                StanzaErrorCondition::ResourceConstraint
            ))
        ));
        assert_eq!(
            test.backlog(&owner)
                .await?
                .ok_or("missing backlog")?
                .messages
                .len(),
            100
        );
        Ok(())
    })
}

#[test]
fn offline_registers_message_and_account_handlers() -> TestResult {
    let offline = Arc::new(Offline::new(BTreeMap::new()));
    let extension: &TestExtension = offline.as_ref();
    assert_eq!(extension.name(), super::NAME);
    let mut catalog = Extensions::<GlobalChunkAllocator, RedbStorage>::default();
    catalog.register(offline.clone())?;
    let registry = catalog.enable_host("example.com", ["offline"])?;
    assert!(registry.messages().is_some());
    assert!(registry.iq().is_empty());
    assert!(
        PresenceRequestType::ALL
            .into_iter()
            .all(|kind| registry.presence().find(kind).is_none())
    );
    assert!(registry.stream_features().is_empty());
    let handlers = registry.account_handlers();
    assert_eq!(handlers.len(), 1);
    assert_eq!(handlers[0].0, "offline");
    let handler: Arc<TestAccountHandler> = offline;
    assert!(Arc::ptr_eq(&handlers[0].1, &handler));
    Ok(())
}

#[test]
fn offline_storage_failure_categories_and_policy_conditions_remain_separate() -> TestResult {
    use crate::delivery::{Failure, FailureKind};
    use lonewolf_storage::{StorageError, StorageErrorKind};
    let mut arena = Arena::try_new(Default::default())?;
    let recipient =
        AccountKey::try_from(Jid::parse_in("bob@example.com", &mut arena)?.resolve(&arena)?)?;
    for kind in [
        StorageErrorKind::Unavailable,
        StorageErrorKind::CorruptData,
        StorageErrorKind::UnsupportedVersion,
        StorageErrorKind::CommitUnknown,
        StorageErrorKind::Other,
    ] {
        for operation in [
            "offline_count",
            "offline_push",
            "offline_backlog",
            "offline_acknowledge",
            "offline_clear",
        ] {
            let error = super::store_error(
                lonewolf_storage::offline::OfflineError::Storage(StorageError::with_source(
                    kind,
                    std::io::Error::other("seeded-sensitive-backend-source"),
                )),
                &recipient,
                operation,
            );
            assert_eq!(error.condition(), StanzaErrorCondition::InternalServerError);
            assert_eq!(
                error.failure(),
                Some(Failure {
                    kind: FailureKind::Storage(kind),
                    operation
                })
            );
            assert!(!format!("{error:?}").contains("seeded-sensitive-backend-source"));
        }
    }
    for (cause, condition) in [
        (
            lonewolf_storage::offline::OfflineError::NoAccount,
            StanzaErrorCondition::ServiceUnavailable,
        ),
        (
            lonewolf_storage::offline::OfflineError::ValueTooLarge,
            StanzaErrorCondition::ResourceConstraint,
        ),
    ] {
        let error = super::offline_error(cause, "offline_push");
        assert_eq!(error.condition(), condition);
        assert_eq!(error.failure(), None);
    }
    Ok(())
}
