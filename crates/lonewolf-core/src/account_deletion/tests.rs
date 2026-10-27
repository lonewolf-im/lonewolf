// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::future::Future;
use std::io;
use std::num::NonZeroUsize;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use compio::runtime::Runtime;
use compio::time::{sleep, timeout};
use futures_util::{FutureExt, poll, select_biased};
use lonewolf_admin::DeleterError;
use lonewolf_auth::scram::{
    SCRAM_POLICY_ITERATIONS, ScramCredentials, ScramSha1Verifier, ScramVerifier,
};
use lonewolf_storage::account::{AccountKey, AccountReads, AccountWrites, NewAccount};
use lonewolf_storage::offline::{OfflineReads, OfflineWrites};
use lonewolf_storage::vcard::{MAX_VCARD_BYTES, VCardQuota, VCardReads, VCardWrites};
use lonewolf_storage::{RedbStorage, Storage, StorageErrorKind, WriteTransaction};
use lonewolf_util::arena::{Arena, ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use redb::backends::InMemoryBackend;
use redb::{
    Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, StorageBackend,
    TableDefinition,
};

use super::delete;
use crate::config::Config;
use crate::hosts::Hosts;
use crate::router::Router;
use crate::router::local::{LocalRouter, RetireCause};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const CARD: &str = "<vCard xmlns='vcard-temp'><FN>Alice</FN></vCard>";
const OTHER_CARD: &str = "<vCard xmlns='vcard-temp'><FN>Bob</FN></vCard>";
const VCARDS: TableDefinition<&str, &[u8]> = TableDefinition::new("lonewolf_vcards");
const MESSAGES: TableDefinition<(&str, u64), &[u8]> =
    TableDefinition::new("lonewolf_offline_messages");
const SEQUENCES: TableDefinition<&str, u64> = TableDefinition::new("lonewolf_offline_sequences");

fn run_test(test: impl Future<Output = TestResult>) -> TestResult {
    Runtime::new()?.block_on(timeout(Duration::from_secs(5), test))?
}

fn key(value: &str) -> TestResult<AccountKey> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let jid = Jid::parse_in(value, &mut arena)?;
    Ok(AccountKey::try_from(jid.resolve(&arena)?)?)
}

fn new_account(key: &AccountKey) -> NewAccount {
    NewAccount {
        key: key.clone(),
        credentials: ScramCredentials::new(ScramVerifier::Sha1(ScramSha1Verifier::new(
            [1; 16],
            SCRAM_POLICY_ITERATIONS,
            [2; 20],
            [3; 20],
        ))),
    }
}

fn storage(backend: impl StorageBackend) -> TestResult<RedbStorage> {
    Ok(RedbStorage::new(
        Database::builder()
            .set_cache_size(1024 * 1024)
            .create_with_backend(backend)?,
    )?)
}

fn router() -> TestResult<Router<GlobalChunkAllocator>> {
    let mut config = Config::default();
    for host in config.hosts.values_mut() {
        host.extensions.clear();
    }
    let hosts = Hosts::new(&config.hosts, config.xmpp.default_host.as_deref())?;
    Ok(Router::new(hosts, LocalRouter::new(GlobalChunkAllocator)))
}

async fn seed(storage: &RedbStorage, owner: &AccountKey, card: &str) -> TestResult {
    let mut transaction = storage.begin_write().await?;
    transaction.create_account(new_account(owner)).await?;
    transaction
        .replace_vcard(owner, card, VCardQuota::default())
        .await?;
    transaction
        .push_offline_message(owner, 10, b"<message/>")
        .await?;
    transaction.commit().await?;
    Ok(())
}

#[test]
fn disabled_extension_cleanup_is_atomic_and_recreation_has_no_previous_card() -> TestResult {
    run_test(async {
        let storage = storage(InMemoryBackend::new())?;
        let router = router()?;
        let handle = router.handle();
        let alice = key("Alice@LOCALHOST")?;
        let bob = key("bob@localhost")?;
        assert!(handle.account_handlers(alice.domain()).is_empty());
        seed(&storage, &alice, CARD).await?;
        seed(&storage, &bob, OTHER_CARD).await?;
        let before = storage.begin_read().await?;
        let raw_before = storage.as_ref().begin_read()?;

        assert!(delete(&alice, &storage, &handle, &GlobalChunkAllocator).await?);

        assert!(before.account(&alice).await?.is_some());
        assert_eq!(
            before
                .vcard(&alice)
                .await?
                .ok_or("old card missing")?
                .xml
                .as_ref(),
            CARD
        );
        assert_eq!(before.offline_count(&alice).await?, 1);
        let after = storage.begin_read().await?;
        assert!(after.account(&alice).await?.is_none());
        assert!(after.vcard(&alice).await?.is_none());
        assert_eq!(after.offline_count(&alice).await?, 0);
        assert!(after.account(&bob).await?.is_some());
        assert_eq!(
            after
                .vcard(&bob)
                .await?
                .ok_or("other card missing")?
                .xml
                .as_ref(),
            OTHER_CARD
        );
        assert_eq!(after.offline_count(&bob).await?, 1);
        let raw_after = storage.as_ref().begin_read()?;
        for name in [
            "lonewolf_accounts",
            "lonewolf_vcards",
            "lonewolf_scram_decoy",
            "lonewolf_roster_items",
            "lonewolf_roster_pending_subscriptions",
        ] {
            let definition: TableDefinition<&str, &[u8]> = TableDefinition::new(name);
            let old = raw_before.open_table(definition)?;
            let new = raw_after.open_table(definition)?;
            let deletes_owner = matches!(name, "lonewolf_accounts" | "lonewolf_vcards");
            assert_eq!(new.len()?, old.len()? - u64::from(deletes_owner), "{name}");
            for entry in old.iter()? {
                let (owner, value) = entry?;
                let current = new.get(owner.value())?;
                if deletes_owner && owner.value() == alice.as_str() {
                    assert!(current.is_none());
                } else {
                    assert_eq!(
                        current.ok_or("unrelated row missing")?.value(),
                        value.value(),
                        "{name}"
                    );
                }
            }
        }
        for name in ["lonewolf_roster_versions", "lonewolf_offline_sequences"] {
            let definition: TableDefinition<&str, u64> = TableDefinition::new(name);
            let old = raw_before.open_table(definition)?;
            let new = raw_after.open_table(definition)?;
            let deletes_owner = name == "lonewolf_offline_sequences";
            assert_eq!(new.len()?, old.len()? - u64::from(deletes_owner), "{name}");
            for entry in old.iter()? {
                let (owner, value) = entry?;
                let current = new.get(owner.value())?;
                if deletes_owner && owner.value() == alice.as_str() {
                    assert!(current.is_none());
                } else {
                    assert_eq!(
                        current.ok_or("unrelated row missing")?.value(),
                        value.value(),
                        "{name}"
                    );
                }
            }
        }
        let old = raw_before.open_table(MESSAGES)?;
        let new = raw_after.open_table(MESSAGES)?;
        assert_eq!(new.len()?, old.len()? - 1);
        for entry in old.iter()? {
            let (key, value) = entry?;
            let current = new.get(key.value())?;
            if key.value().0 == alice.as_str() {
                assert!(current.is_none());
            } else {
                assert_eq!(
                    current.ok_or("other message missing")?.value(),
                    value.value()
                );
            }
        }

        let mut transaction = storage.begin_write().await?;
        transaction
            .create_account(new_account(&key("alice@localhost")?))
            .await?;
        transaction.commit().await?;
        assert!(storage.begin_read().await?.vcard(&alice).await?.is_none());
        assert!(delete(&alice, &storage, &handle, &GlobalChunkAllocator).await?);
        assert!(!delete(&alice, &storage, &handle, &GlobalChunkAllocator).await?);
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn missing_account_cleanup_removes_orphaned_invalid_and_oversized_raw_cards() -> TestResult {
    run_test(async {
        let storage = storage(InMemoryBackend::new())?;
        let router = router()?;
        let handle = router.handle();
        let alice = key("alice@localhost")?;
        for bytes in [
            CARD.as_bytes().to_vec(),
            b"<not-valid-xml\xff".to_vec(),
            vec![b'x'; MAX_VCARD_BYTES + 1],
        ] {
            let transaction = storage.as_ref().begin_write()?;
            transaction
                .open_table(VCARDS)?
                .insert(alice.as_str(), bytes.as_slice())?;
            transaction.commit()?;
            assert!(!delete(&alice, &storage, &handle, &GlobalChunkAllocator).await?);
            assert!(storage.begin_read().await?.vcard(&alice).await?.is_none());
            assert!(!delete(&alice, &storage, &handle, &GlobalChunkAllocator).await?);
        }
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn precommit_offline_cleanup_failure_preserves_account_card_and_session() -> TestResult {
    run_test(async {
        let storage = storage(InMemoryBackend::new())?;
        let router = router()?;
        let handle = router.handle();
        let alice = key("alice@localhost")?;
        seed(&storage, &alice, CARD).await?;
        let session = handle
            .register(&alice, Some("desk"), NonZeroUsize::MIN)
            .await?;
        let transaction = storage.as_ref().begin_write()?;
        transaction.delete_table(SEQUENCES)?;
        let wrong_type: TableDefinition<&str, &str> =
            TableDefinition::new("lonewolf_offline_sequences");
        transaction
            .open_table(wrong_type)?
            .insert(alice.as_str(), "invalid")?;
        transaction.commit()?;

        let error = delete(&alice, &storage, &handle, &GlobalChunkAllocator)
            .await
            .expect_err("cleanup accepted a wrong table type");
        assert!(
            matches!(error, DeleterError::Storage(error) if error.kind() == StorageErrorKind::CorruptData)
        );
        let after = storage.begin_read().await?;
        assert!(after.account(&alice).await?.is_some());
        assert_eq!(
            after
                .vcard(&alice)
                .await?
                .ok_or("card changed")?
                .xml
                .as_ref(),
            CARD
        );
        assert_eq!(after.offline_count(&alice).await?, 1);
        assert!(session.liveness().is_alive());
        drop(session);
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn precommit_vcard_cleanup_failure_rolls_back_account_and_offline_cleanup() -> TestResult {
    run_test(async {
        let storage = storage(InMemoryBackend::new())?;
        let router = router()?;
        let handle = router.handle();
        let alice = key("alice@localhost")?;
        seed(&storage, &alice, CARD).await?;
        let transaction = storage.as_ref().begin_write()?;
        transaction.delete_table(VCARDS)?;
        let wrong_type: TableDefinition<&str, &str> = TableDefinition::new("lonewolf_vcards");
        transaction
            .open_table(wrong_type)?
            .insert(alice.as_str(), CARD)?;
        transaction.commit()?;

        let error = delete(&alice, &storage, &handle, &GlobalChunkAllocator)
            .await
            .expect_err("cleanup accepted a wrong table type");
        assert!(
            matches!(error, DeleterError::Storage(error) if error.kind() == StorageErrorKind::CorruptData)
        );
        let after = storage.begin_read().await?;
        assert!(after.account(&alice).await?.is_some());
        assert_eq!(after.offline_count(&alice).await?, 1);
        let raw = storage.as_ref().begin_read()?;
        assert_eq!(
            raw.open_table(wrong_type)?
                .get(alice.as_str())?
                .ok_or("card changed")?
                .value(),
            CARD
        );
        assert_eq!(
            raw.open_table(SEQUENCES)?
                .get(alice.as_str())?
                .ok_or("sequence changed")?
                .value(),
            1
        );
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn deletion_waits_for_older_effects_before_session_retirement_and_completion() -> TestResult {
    run_test(async {
        let storage = storage(InMemoryBackend::new())?;
        let router = router()?;
        let handle = router.handle();
        let alice = key("alice@localhost")?;
        seed(&storage, &alice, CARD).await?;
        let session = handle
            .register(&alice, Some("desk"), NonZeroUsize::MIN)
            .await?;
        let (_, older) = handle
            .order()
            .fix(vec![key("bob@localhost")?], async { TestResult::Ok(()) })
            .await?;
        let mut deletion = Box::pin(delete(&alice, &storage, &handle, &GlobalChunkAllocator));
        let committed = async {
            loop {
                if storage.begin_read().await?.account(&alice).await?.is_none() {
                    return TestResult::Ok(());
                }
                sleep(Duration::from_millis(1)).await;
            }
        };
        select_biased! {
            result = deletion.as_mut().fuse() => { result?; return Err("deletion completed ahead of older effects".into()); },
            result = committed.fuse() => result?,
        }
        assert!(storage.begin_read().await?.vcard(&alice).await?.is_none());
        assert!(session.liveness().is_alive());
        let carol = key("carol@localhost")?;
        // The commit is visible before the deletion is polled to admit its barrier and release the ordering lock.
        let (_, mut later) = select_biased! {
            result = deletion.as_mut().fuse() => { result?; return Err("deletion completed ahead of older effects".into()); },
            later = handle.order().fix(vec![carol], async { TestResult::Ok(()) }).fuse() => later?,
        };
        assert!(poll!(deletion.as_mut()).is_pending());
        assert!(poll!(pin!(later.turn())).is_pending());
        drop(older);
        assert!(deletion.await?);
        assert!(!session.liveness().is_alive());
        assert_eq!(
            session.wait_retired().await?.cause,
            RetireCause::AccountDeleted
        );
        later.turn().await;
        drop(later);
        drop(session);
        router.shutdown().await?;
        Ok(())
    })
}

#[derive(Clone, Debug, Default)]
struct FailingSyncBackend {
    inner: Arc<InMemoryBackend>,
    fail_next_sync: Arc<AtomicBool>,
}

impl StorageBackend for FailingSyncBackend {
    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.inner.read(offset, out)
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.inner.set_len(len)
    }

    fn sync_data(&self) -> io::Result<()> {
        self.inner.sync_data()?;
        if self.fail_next_sync.swap(false, Ordering::SeqCst) {
            Err(io::Error::other("injected sync failure"))
        } else {
            Ok(())
        }
    }

    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.inner.write(offset, data)
    }
}

#[test]
fn submitted_deletion_commit_failure_remains_typed_and_recovery_keeps_state_atomic() -> TestResult {
    run_test(async {
        let backend = FailingSyncBackend::default();
        let alice = key("alice@localhost")?;
        {
            let storage = storage(backend.clone())?;
            let router = router()?;
            let handle = router.handle();
            seed(&storage, &alice, CARD).await?;
            backend.fail_next_sync.store(true, Ordering::SeqCst);
            let error = delete(&alice, &storage, &handle, &GlobalChunkAllocator)
                .await
                .expect_err("sync failure accepted");
            assert!(
                matches!(error, DeleterError::Storage(error) if error.kind() == StorageErrorKind::CommitUnknown)
            );
            router.shutdown().await?;
        }
        let storage = storage(backend)?;
        let after = storage.begin_read().await?;
        let account_exists = after.account(&alice).await?.is_some();
        assert_eq!(after.vcard(&alice).await?.is_some(), account_exists);
        assert_eq!(
            after.offline_count(&alice).await?,
            usize::from(account_exists)
        );
        if account_exists {
            assert_eq!(
                after
                    .vcard(&alice)
                    .await?
                    .ok_or("card missing")?
                    .xml
                    .as_ref(),
                CARD
            );
        }
        Ok(())
    })
}
