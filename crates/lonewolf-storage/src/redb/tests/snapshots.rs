// SPDX-License-Identifier: Apache-2.0

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::Ordering;
use std::sync::{Arc, mpsc};

use futures_executor::block_on;

use super::backend::{FailingSyncBackend, ObservedBackend};
use super::database;
use crate::account::{AccountReads, AccountWrites};
use crate::metrics::ReadSnapshot;
use crate::redb::{RetireSnapshot, can_share};
use crate::tests::{TIMEOUT, TestResult, assert_storage_error, new_account, poll};
use crate::vcard::{VCardQuota, VCardReads, VCardWrites};
use crate::{CommitObserver, RedbBackend, Storage, StorageErrorKind, WriteTransaction};

impl RedbBackend {
    fn generation(&self) -> u64 {
        self.inner.commits.load(Ordering::Acquire)
    }

    fn has_shared_snapshot(&self) -> bool {
        self.inner.shared.lock().is_some()
    }
}

fn file_backend() -> TestResult<(tempfile::TempDir, RedbBackend)> {
    let directory = tempfile::tempdir()?;
    let backend = RedbBackend::open(directory.path().join("store.redb"))?;
    Ok((directory, backend))
}

#[test]
fn readers_share_a_snapshot_until_the_next_commit() -> TestResult {
    let (_directory, storage) = file_backend()?;
    block_on(async {
        let first = storage.begin_read().await?;
        let second = storage.clone().begin_read().await?;
        assert!(Arc::ptr_eq(&first.snapshot(), &second.snapshot()));
        assert_eq!(
            storage.metrics().read_snapshots().collect::<Vec<_>>(),
            [(ReadSnapshot::Reused, 1), (ReadSnapshot::Opened, 1)],
        );
        Ok(())
    })
}

#[test]
fn commit_retires_the_shared_snapshot() -> TestResult {
    let (_directory, storage) = file_backend()?;
    let account = new_account("alice@example.test", 1)?;
    let owner = account.key.clone();
    block_on(async {
        let mut writer = storage.begin_write().await?;
        writer.create_account(account).await?;
        writer.commit().await?;
        let first = storage.begin_read().await?;
        assert!(first.vcard(&owner).await?.is_none());

        let mut writer = storage.begin_write().await?;
        writer
            .replace_vcard(&owner, "<vCard/>", VCardQuota::default())
            .await?;
        writer.commit().await?;
        assert!(!storage.has_shared_snapshot());
        let second = storage.begin_read().await?;
        assert!(!Arc::ptr_eq(&first.snapshot(), &second.snapshot()));
        let card = second.vcard(&owner).await?.ok_or("missing vCard")?;
        assert_eq!(card.xml.as_ref(), "<vCard/>");
        assert!(first.vcard(&owner).await?.is_none());
        Ok(())
    })
}

#[test]
fn cancelled_commit_retires_the_shared_snapshot() -> TestResult {
    let backend = ObservedBackend::default();
    let storage = RedbBackend::new(database(backend.clone(), 1024 * 1024)?)?;
    let account = new_account("alice@example.test", 1)?;
    let owner = account.key.clone();
    block_on(async {
        let first = storage.begin_read().await?;
        let mut writer = storage.begin_write().await?;
        writer.create_account(account).await?;
        let (entered, release) = backend.block_next_sync()?;
        let mut commit = Box::pin(writer.commit());
        assert!(poll(commit.as_mut()).is_pending());
        entered.recv_timeout(TIMEOUT)?;
        drop(commit);
        release.send(())?;

        drop(storage.begin_write().await?);
        let second = storage.begin_read().await?;
        assert!(!Arc::ptr_eq(&first.snapshot(), &second.snapshot()));
        assert!(second.account(&owner).await?.is_some());
        assert_eq!(
            storage.metrics().read_snapshots().collect::<Vec<_>>(),
            [(ReadSnapshot::Reused, 0), (ReadSnapshot::Opened, 2)],
        );
        Ok(())
    })
}

#[test]
fn share_decision_rejects_snapshots_raced_by_a_commit() {
    assert!(!can_share(None, 3, 2, 3));
    assert!(!can_share(None, 3, 2, 2));
    assert!(!can_share(Some(4), 3, 3, 3));
    assert!(!can_share(Some(3), 3, 3, 3));
    assert!(can_share(Some(2), 3, 3, 3));
    assert!(can_share(None, 3, 3, 3));
}

#[test]
fn delayed_publication_does_not_restore_a_retired_generation() -> TestResult {
    let (_directory, storage) = file_backend()?;
    let account = new_account("alice@example.test", 1)?;
    let owner = account.key.clone();
    block_on(async {
        let snapshot = storage.begin_read().await?.snapshot();
        let generation = storage.generation();
        let mut writer = storage.begin_write().await?;
        writer.create_account(account).await?;
        writer.commit().await?;
        storage
            .inner
            .share_snapshot(&snapshot, generation, generation);
        assert!(!storage.has_shared_snapshot());
        assert!(storage.begin_read().await?.account(&owner).await?.is_some());
        Ok(())
    })
}

struct CommitProbe {
    storage: RedbBackend,
    before: Option<u64>,
    succeeds: bool,
    completion: mpsc::Sender<()>,
}

impl CommitObserver for CommitProbe {
    fn before_commit(&mut self) {
        assert!(self.storage.has_shared_snapshot());
        self.before = Some(self.storage.generation());
    }

    fn after_commit(&mut self, committed: bool) {
        assert_eq!(committed, self.succeeds);
        assert_eq!(Some(self.storage.generation() - 1), self.before);
        assert!(!self.storage.has_shared_snapshot());
        let _ = self.completion.send(());
    }
}

#[test]
fn generation_moves_inside_the_observer_bracket() -> TestResult {
    let (_directory, storage) = file_backend()?;
    block_on(async {
        drop(storage.begin_read().await?);
        let (completion, observed) = mpsc::channel();
        storage
            .begin_write()
            .await?
            .commit_observed(CommitProbe {
                storage: storage.clone(),
                before: None,
                succeeds: true,
                completion,
            })
            .await?;
        observed.try_recv()?;
        assert_eq!(storage.generation(), 1);
        assert!(!storage.has_shared_snapshot());
        Ok(())
    })
}

#[test]
fn failed_commit_retires_the_shared_snapshot_before_the_observer() -> TestResult {
    let backend = FailingSyncBackend::default();
    let storage = RedbBackend::new(database(backend.clone(), 1024 * 1024)?)?;
    block_on(async {
        drop(storage.begin_read().await?);
        let mut writer = storage.begin_write().await?;
        writer
            .create_account(new_account("alice@example.test", 1)?)
            .await?;
        backend.fail_next_sync();
        let (completion, observed) = mpsc::channel();
        let result = writer
            .commit_observed(CommitProbe {
                storage: storage.clone(),
                before: None,
                succeeds: false,
                completion,
            })
            .await;
        assert_storage_error(result, StorageErrorKind::CommitUnknown);
        observed.try_recv()?;
        assert_eq!(storage.generation(), 1);
        assert!(!storage.has_shared_snapshot());
        Ok(())
    })
}

#[test]
fn retirement_guard_releases_the_shared_transaction_on_unwind() -> TestResult {
    let (_directory, storage) = file_backend()?;
    let snapshot = Arc::downgrade(&block_on(storage.begin_read())?.snapshot());
    assert!(snapshot.upgrade().is_some());
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _retirement = RetireSnapshot(Some(&storage.inner));
        panic!("injected commit unwind");
    }));
    assert!(result.is_err());
    assert_eq!(storage.generation(), 1);
    assert!(!storage.has_shared_snapshot());
    assert!(snapshot.upgrade().is_none());
    Ok(())
}
