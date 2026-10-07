// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use compio::runtime::Runtime;
use futures_channel::oneshot;
use lonewolf_auth::scram::{ScramCredentials, ScramHash, ScramVerifier};
use lonewolf_storage::account::*;
use lonewolf_storage::offline::*;
use lonewolf_storage::roster::*;
use lonewolf_storage::{ReadTransaction, StorageError, StorageErrorKind, WriteTransaction};
use lonewolf_util::arena::GlobalChunkAllocator;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

use super::tests::{NoDelivery, TestResult, account};
use super::*;

pub(crate) const SENSITIVE_SOURCE: &str = "seeded-password-XML-IP-stream-id-client-stanza-id";

pub(crate) const KINDS: [StorageErrorKind; 5] = [
    StorageErrorKind::Unavailable,
    StorageErrorKind::CorruptData,
    StorageErrorKind::UnsupportedVersion,
    StorageErrorKind::CommitUnknown,
    StorageErrorKind::Other,
];

pub(crate) fn seeded_error(kind: StorageErrorKind) -> StorageError {
    StorageError::with_source(kind, std::io::Error::other(SENSITIVE_SOURCE))
}

#[derive(Clone, Default)]
pub(crate) struct Capture(Arc<Mutex<Vec<BTreeMap<&'static str, String>>>>);

struct Fields(BTreeMap<&'static str, String>);
impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name(), value.into());
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name(), format!("{value:?}"));
    }
}

impl Subscriber for Capture {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut fields = Fields(BTreeMap::new());
        event.record(&mut fields);
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(fields.0);
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

impl Capture {
    pub(crate) fn assert_one(&self, kind: FailureKind, operation: &str) {
        let events = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let matching: Vec<_> = events
            .iter()
            .filter(|fields| {
                fields
                    .get("message")
                    .is_some_and(|value| value == "internal operation failed")
            })
            .collect();
        assert_eq!(matching.len(), 1, "{events:?}");
        assert_eq!(
            matching[0].get("operation").map(String::as_str),
            Some(operation)
        );
        assert_eq!(
            matching[0].get("failure_kind").map(String::as_str),
            Some(kind.as_str())
        );
        assert!(!format!("{events:?}").contains(SENSITIVE_SOURCE));
        assert!(!format!("{events:?}").contains("private-client-stanza-id"));
        for key in [
            "payload",
            "password",
            "ip",
            "stream_id",
            "stanza_id",
            "error",
        ] {
            assert!(!matching[0].contains_key(key));
        }
    }
}

struct FailedCommit {
    kind: StorageErrorKind,
    release: oneshot::Receiver<()>,
}
impl ReadTransaction for FailedCommit {}
impl WriteTransaction for FailedCommit {
    async fn commit(self) -> Result<(), StorageError> {
        let _ = self.release.await;
        Err(seeded_error(self.kind))
    }
}

impl AccountReads for FailedCommit {
    async fn account(&self, _key: &AccountKey) -> Result<Option<Account>, AccountError> {
        unreachable!("commit test cannot use storage operations")
    }
    async fn scram(
        &self,
        _key: &AccountKey,
        _hash: ScramHash,
    ) -> Result<Option<ScramVerifier>, AccountError> {
        unreachable!("commit test cannot use storage operations")
    }
    async fn accounts_after(
        &self,
        _after: Option<&AccountKey>,
        _limit: NonZeroUsize,
    ) -> Result<Vec<Account>, AccountError> {
        unreachable!("commit test cannot use storage operations")
    }
}

impl AccountWrites for FailedCommit {
    async fn create_account(&mut self, _account: NewAccount) -> Result<(), AccountError> {
        unreachable!("commit test cannot use storage operations")
    }
    async fn delete_account(&mut self, _key: &AccountKey) -> Result<(), AccountError> {
        unreachable!("commit test cannot use storage operations")
    }
    async fn replace_credentials(
        &mut self,
        _key: &AccountKey,
        _credentials: ScramCredentials,
    ) -> Result<(), AccountError> {
        unreachable!("commit test cannot use storage operations")
    }
}

impl OfflineReads for FailedCommit {
    async fn offline_messages(
        &self,
        _owner: &AccountKey,
    ) -> Result<Vec<StoredMessage>, OfflineError> {
        unreachable!("commit test cannot use storage operations")
    }
    async fn offline_count(&self, _owner: &AccountKey) -> Result<usize, OfflineError> {
        unreachable!("commit test cannot use storage operations")
    }
}

impl OfflineWrites for FailedCommit {
    async fn push_offline_message(
        &mut self,
        _owner: &AccountKey,
        _stored_at: u64,
        _stanza: &[u8],
    ) -> Result<OfflineSequence, OfflineError> {
        unreachable!("commit test cannot use storage operations")
    }
    async fn remove_offline_messages_through(
        &mut self,
        _owner: &AccountKey,
        _through: OfflineSequence,
    ) -> Result<usize, OfflineError> {
        unreachable!("commit test cannot use storage operations")
    }
    async fn remove_offline_message(
        &mut self,
        _owner: &AccountKey,
        _sequence: OfflineSequence,
    ) -> Result<bool, OfflineError> {
        unreachable!("commit test cannot use storage operations")
    }
    async fn clear_offline_messages(&mut self, _owner: &AccountKey) -> Result<(), OfflineError> {
        unreachable!("commit test cannot use storage operations")
    }
}

impl RosterReads for FailedCommit {
    async fn roster(&self, _owner: &AccountKey) -> Result<RosterSnapshot, RosterError> {
        unreachable!("commit test cannot use storage operations")
    }
    async fn roster_item(
        &self,
        _owner: &AccountKey,
        _jid: &RosterJid,
    ) -> Result<Option<RosterItem>, RosterError> {
        unreachable!("commit test cannot use storage operations")
    }
    async fn pending_requests(
        &self,
        _owner: &AccountKey,
    ) -> Result<Vec<PendingSubscription>, RosterError> {
        unreachable!("commit test cannot use storage operations")
    }
    async fn pending_request(
        &self,
        _owner: &AccountKey,
        _sender: &RosterJid,
    ) -> Result<Option<PendingSubscription>, RosterError> {
        unreachable!("commit test cannot use storage operations")
    }
}

impl RosterWrites for FailedCommit {
    async fn put_roster_item(
        &mut self,
        _owner: &AccountKey,
        _item: &RosterItem,
    ) -> Result<RosterVersion, RosterError> {
        unreachable!("commit test cannot use storage operations")
    }
    async fn remove_roster_item(
        &mut self,
        _owner: &AccountKey,
        _jid: &RosterJid,
    ) -> Result<Option<RosterMutation<RosterItem>>, RosterError> {
        unreachable!("commit test cannot use storage operations")
    }
    async fn put_pending_request(
        &mut self,
        _owner: &AccountKey,
        _request: PendingSubscription,
        _max_pending_subscription_requests: NonZeroUsize,
    ) -> Result<(), RosterError> {
        unreachable!("commit test cannot use storage operations")
    }
    async fn remove_pending_request(
        &mut self,
        _owner: &AccountKey,
        _sender: &RosterJid,
    ) -> Result<bool, RosterError> {
        unreachable!("commit test cannot use storage operations")
    }
    async fn clear_roster(&mut self, _owner: &AccountKey) -> Result<(), RosterError> {
        unreachable!("commit test cannot use storage operations")
    }
}

#[test]
fn detached_commit_failures_keep_categories_and_log_after_requester_cancellation() -> TestResult {
    for kind in KINDS {
        let capture = Capture::default();
        let _subscriber = tracing::subscriber::set_default(capture.clone());
        Runtime::new()?.block_on(async {
            let owner = account("alice@example.com")?;
            let (release, blocked) = oneshot::channel();
            let mut group = WorkGroup::new();
            let effects: Effects<GlobalChunkAllocator> = Effects::new(vec![owner.clone()], |_| {
                panic!("failed commit must not run effects")
            });
            let pending = commit_and_deliver(
                group.start(),
                Order::new(),
                FailedCommit {
                    kind,
                    release: blocked,
                },
                effects,
                NoDelivery,
                None,
                EffectsDiagnostics {
                    account: owner,
                    commit_operation: "iq_set_commit",
                    delivery_operation: "iq_set_effects",
                },
            );
            drop(pending);
            release.send(()).map_err(|_| "commit owner was cancelled")?;
            compio::time::timeout(Duration::from_secs(1), group.drain()).await?;
            capture.assert_one(FailureKind::Storage(kind), "iq_set_commit");
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    }
    Ok(())
}

#[test]
fn detached_effect_failure_logs_after_requester_cancellation() -> TestResult {
    let capture = Capture::default();
    let _subscriber = tracing::subscriber::set_default(capture.clone());
    Runtime::new()?.block_on(async {
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
        let owner = account("alice@example.com")?;
        let (release, blocked) = oneshot::channel();
        let effects = Effects::new(vec![owner.clone()], move |_| {
            Box::pin(async move {
                let _ = blocked.await;
                Err(DeliveryError)
            })
        });
        let mut group = WorkGroup::new();
        let pending = commit_and_deliver(
            group.start(),
            Order::new(),
            storage.begin_write().await?,
            effects,
            NoDelivery,
            None,
            EffectsDiagnostics {
                account: owner,
                commit_operation: "presence_subscription_commit",
                delivery_operation: "presence_subscription_effects",
            },
        );
        drop(pending);
        release.send(()).map_err(|_| "effect owner was cancelled")?;
        compio::time::timeout(Duration::from_secs(1), group.drain()).await?;
        capture.assert_one(FailureKind::Delivery, "presence_subscription_effects");
        Ok(())
    })
}
