// SPDX-License-Identifier: Apache-2.0

use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread::{self, ThreadId};

use futures_executor::block_on;
use lonewolf_auth::server::ScramDecoy;
use lonewolf_util::arena::Arena;
use lonewolf_xmpp::jid::Jid;

use super::blocklist::BlocklistCache;
use super::{BlocklistFill, BlocklistLookup, BlocklistUpdate, CachedStorage};
use crate::account::{AccountKey, AccountReads, AccountWrites};
use crate::blocking::redb::ITEMS;
use crate::blocking::{BlockChange, BlockingReads, BlockingWrites};
use crate::offline::{OfflineReads, OfflineWrites};
use crate::private::{PrivateXmlChange, PrivateXmlQuota, PrivateXmlReads, PrivateXmlWrites};
use crate::roster::{
    RosterQuota, RosterReads, RosterSubscription, RosterWrites, SubscriptionState,
};
use crate::tests::{TIMEOUT, TestResult, item, jid, key, new_account, poll};
use crate::vcard::{VCardQuota, VCardReads, VCardWrites};
use crate::{
    CommitObserver, RedbBackend, RedbBackendRead, RedbBackendWrite, RedbStorage, Storage,
    StorageError, WriteTransaction,
};

const ALICE: &str = "alice@example.test";
const BOB: &str = "bob@example.test";
const CAROL: &str = "carol@example.test";

async fn is_blocked(
    reader: &impl BlockingReads,
    owner: &AccountKey,
    peer: &str,
) -> TestResult<bool> {
    let mut arena = Arena::try_new(Default::default())?;
    let peer = Jid::parse_in(peer, &mut arena)?;
    Ok(reader.is_blocked(owner, peer.resolve(&arena)?).await?)
}

async fn create_cache_test_accounts(storage: &RedbStorage) -> TestResult {
    let mut writer = storage.begin_write().await?;
    writer.create_account(new_account(ALICE, 1)?).await?;
    writer.create_account(new_account(BOB, 2)?).await?;
    writer.create_account(new_account(CAROL, 3)?).await?;
    writer.commit().await?;
    Ok(())
}

async fn set_block(storage: &RedbStorage, owner: &AccountKey, peer: &str) -> TestResult {
    let mut writer = storage.begin_write().await?;
    writer
        .change_blocklist(owner, BlockChange::Block(&[jid(peer)?]))
        .await?;
    writer.commit().await?;
    Ok(())
}

fn lookup_counts(storage: &RedbStorage) -> Vec<(BlocklistLookup, u64)> {
    storage.cache_metrics().blocklist_lookups().collect()
}

fn file_store() -> TestResult<(tempfile::TempDir, RedbStorage)> {
    let directory = tempfile::tempdir()?;
    let storage = RedbStorage::open(directory.path().join("storage.redb"))?;
    Ok((directory, storage))
}

#[test]
fn cached_matching_agrees_with_backend_matching() -> TestResult {
    const PEERS: &[&str] = &[
        "u@d/r",
        "u@d/s",
        "u@d",
        "v@d",
        "v@d/r",
        "d/r",
        "d/s",
        "d",
        "x@other/r",
        "y@other",
    ];
    let (_directory, storage) = file_store()?;
    let owner = key(ALICE)?;
    let rules = ["u@d/r", "u@d", "d/r", "d", "x@other"].map(jid);
    let rules = rules.into_iter().collect::<Result<Vec<_>, _>>()?;
    let mut subsets = vec![Vec::new()];
    for (index, first) in rules.iter().enumerate() {
        subsets.push(vec![first.clone()]);
        for second in &rules[index + 1..] {
            subsets.push(vec![first.clone(), second.clone()]);
        }
    }
    block_on(async {
        create_cache_test_accounts(&storage).await?;
        for subset in &subsets {
            let mut writer = storage.begin_write().await?;
            writer.change_blocklist(&owner, BlockChange::Clear).await?;
            writer
                .change_blocklist(&owner, BlockChange::Block(subset))
                .await?;
            writer.commit().await?;
            let reader = storage.begin_read().await?;
            for peer in PEERS {
                assert_eq!(
                    is_blocked(&reader, &owner, peer).await?,
                    is_blocked(reader.inner(), &owner, peer).await?,
                    "peer {peer} in subset {subset:?}",
                );
            }
        }
        assert_eq!(
            lookup_counts(&storage),
            [
                (BlocklistLookup::Hit, (subsets.len() * PEERS.len()) as u64),
                (BlocklistLookup::Miss, 0),
                (BlocklistLookup::Bypass, 0),
            ],
        );
        Ok(())
    })
}

#[test]
fn old_snapshot_keeps_reading_its_own_list_after_a_block() -> TestResult {
    let (_directory, storage) = file_store()?;
    let owner = key(ALICE)?;
    block_on(async {
        create_cache_test_accounts(&storage).await?;
        let old = storage.begin_read().await?;
        assert!(!is_blocked(&old, &owner, BOB).await?);
        set_block(&storage, &owner, BOB).await?;
        assert!(!is_blocked(&old, &owner, BOB).await?);
        let current = storage.begin_read().await?;
        assert!(is_blocked(&current, &owner, BOB).await?);
        assert_eq!(
            lookup_counts(&storage),
            [
                (BlocklistLookup::Hit, 1),
                (BlocklistLookup::Miss, 1),
                (BlocklistLookup::Bypass, 1),
            ]
        );
        Ok(())
    })
}

#[test]
fn load_racing_a_commit_is_not_cached() -> TestResult {
    let (_directory, storage) = file_store()?;
    let alice = key(ALICE)?;
    let carol = key(CAROL)?;
    block_on(async {
        create_cache_test_accounts(&storage).await?;
        let old = storage.begin_read().await?;
        set_block(&storage, &carol, BOB).await?;
        assert!(!is_blocked(&old, &alice, BOB).await?);
        assert_eq!(storage.cache_metrics().blocklist_entries(), 1);
        assert_eq!(
            storage
                .cache_metrics()
                .blocklist_fills()
                .collect::<Vec<_>>(),
            [(BlocklistFill::Inserted, 0), (BlocklistFill::Discarded, 1),]
        );
        let current = storage.begin_read().await?;
        assert!(!is_blocked(&current, &alice, BOB).await?);
        assert_eq!(storage.cache_metrics().blocklist_entries(), 2);
        assert_eq!(
            storage
                .cache_metrics()
                .blocklist_fills()
                .collect::<Vec<_>>(),
            [(BlocklistFill::Inserted, 1), (BlocklistFill::Discarded, 1),]
        );
        assert_eq!(
            lookup_counts(&storage),
            [
                (BlocklistLookup::Hit, 0),
                (BlocklistLookup::Miss, 2),
                (BlocklistLookup::Bypass, 0),
            ]
        );
        Ok(())
    })
}

#[test]
fn write_through_serves_the_next_snapshot_without_a_load() -> TestResult {
    let (_directory, storage) = file_store()?;
    let owner = key(ALICE)?;
    block_on(async {
        create_cache_test_accounts(&storage).await?;
        set_block(&storage, &owner, BOB).await?;
        let reader = storage.begin_read().await?;
        assert!(is_blocked(&reader, &owner, BOB).await?);
        assert_eq!(
            lookup_counts(&storage),
            [
                (BlocklistLookup::Hit, 1),
                (BlocklistLookup::Miss, 0),
                (BlocklistLookup::Bypass, 0),
            ]
        );
        assert_eq!(
            storage
                .cache_metrics()
                .blocklist_updates()
                .collect::<Vec<_>>(),
            [
                (BlocklistUpdate::Written, 1),
                (BlocklistUpdate::Invalidated, 0),
            ]
        );
        Ok(())
    })
}

#[test]
fn account_deletion_removes_the_entry() -> TestResult {
    let (_directory, storage) = file_store()?;
    let owner = key(ALICE)?;
    block_on(async {
        create_cache_test_accounts(&storage).await?;
        set_block(&storage, &owner, BOB).await?;
        assert_eq!(storage.cache_metrics().blocklist_entries(), 1);
        assert!(storage.cache_metrics().blocklist_size_bytes() > 0);
        let mut writer = storage.begin_write().await?;
        writer.delete_blocklist(&owner).await?;
        writer.commit().await?;
        assert_eq!(storage.cache_metrics().blocklist_entries(), 0);
        assert_eq!(storage.cache_metrics().blocklist_size_bytes(), 0);
        let reader = storage.begin_read().await?;
        assert!(reader.blocklist(&owner).await?.is_empty());
        assert_eq!(storage.cache_metrics().blocklist_entries(), 1);
        assert_eq!(
            lookup_counts(&storage),
            [
                (BlocklistLookup::Hit, 0),
                (BlocklistLookup::Miss, 1),
                (BlocklistLookup::Bypass, 0),
            ]
        );
        Ok(())
    })
}

#[test]
fn cancelled_commit_still_updates_the_cache() -> TestResult {
    let (storage, backend) = crate::redb::tests::observed_storage()?;
    let owner = key(ALICE)?;
    block_on(async {
        create_cache_test_accounts(&storage).await?;
        let mut writer = storage.begin_write().await?;
        writer
            .change_blocklist(&owner, BlockChange::Block(&[jid(BOB)?]))
            .await?;
        let (started, release) = backend.block_next_sync()?;
        {
            let mut commit = pin!(writer.commit());
            assert!(poll(commit.as_mut()).is_pending());
            started.recv_timeout(TIMEOUT)?;
        }
        release.send(())?;
        drop(storage.begin_write().await?);
        let reader = storage.begin_read().await?;
        assert!(is_blocked(&reader, &owner, BOB).await?);
        assert_eq!(
            lookup_counts(&storage),
            [
                (BlocklistLookup::Hit, 1),
                (BlocklistLookup::Miss, 0),
                (BlocklistLookup::Bypass, 0),
            ]
        );
        Ok(())
    })
}

#[test]
fn write_transaction_reads_bypass_the_cache() -> TestResult {
    let (_directory, storage) = file_store()?;
    let owner = key(ALICE)?;
    block_on(async {
        create_cache_test_accounts(&storage).await?;
        let reader = storage.begin_read().await?;
        assert!(!is_blocked(&reader, &owner, BOB).await?);
        let lookups = lookup_counts(&storage);
        let mut writer = storage.begin_write().await?;
        writer
            .change_blocklist(&owner, BlockChange::Block(&[jid(BOB)?]))
            .await?;
        assert!(is_blocked(&writer, &owner, BOB).await?);
        assert_eq!(writer.blocklist(&owner).await?, [jid(BOB)?]);
        assert_eq!(lookup_counts(&storage), lookups);
        Ok(())
    })
}

#[test]
fn blocklist_reads_use_and_fill_the_cache() -> TestResult {
    let (directory, storage) = file_store()?;
    let owner = key(ALICE)?;
    let rules = [jid(BOB)?, jid(CAROL)?];
    block_on(async {
        create_cache_test_accounts(&storage).await?;
        let mut writer = storage.begin_write().await?;
        writer
            .change_blocklist(
                &owner,
                BlockChange::Block(&[rules[1].clone(), rules[0].clone()]),
            )
            .await?;
        writer.commit().await?;
        drop(storage);
        let storage = RedbStorage::open(directory.path().join("storage.redb"))?;
        let reader = storage.begin_read().await?;
        let expected = reader.inner().blocklist(&owner).await?;
        assert_eq!(expected, rules);
        assert_eq!(reader.blocklist(&owner).await?, expected);
        assert_eq!(storage.cache_metrics().blocklist_entries(), 1);
        assert_eq!(reader.blocklist(&owner).await?, expected);
        assert_eq!(
            lookup_counts(&storage),
            [
                (BlocklistLookup::Hit, 1),
                (BlocklistLookup::Miss, 1),
                (BlocklistLookup::Bypass, 0),
            ]
        );
        Ok(())
    })
}

#[test]
fn raw_database_exposure_keeps_overlapping_snapshots_consistent_across_clones() -> TestResult {
    let (_directory, storage) = file_store()?;
    let cloned = storage.clone();
    let owner = key(ALICE)?;
    block_on(async {
        create_cache_test_accounts(&storage).await?;
        let before = storage.begin_read().await?;
        assert!(!is_blocked(&before, &owner, BOB).await?);
        assert_eq!(storage.cache_metrics().blocklist_entries(), 1);

        let raw = cloned.as_ref();
        assert_eq!(storage.cache_metrics().blocklist_entries(), 0);
        assert_eq!(storage.cache_metrics().blocklist_size_bytes(), 0);
        let first_write = raw.begin_write()?;
        first_write.open_table(ITEMS)?.insert((ALICE, BOB), ())?;
        first_write.commit()?;
        let first = storage.begin_read().await?;
        assert!(is_blocked(&first, &owner, BOB).await?);

        let second_write = raw.begin_write()?;
        second_write.open_table(ITEMS)?.remove((ALICE, BOB))?;
        second_write.commit()?;
        let second = cloned.begin_read().await?;
        assert!(!is_blocked(&second, &owner, BOB).await?);
        assert_eq!(first.blocklist(&owner).await?, [jid(BOB)?]);
        assert!(before.blocklist(&owner).await?.is_empty());

        set_block(&cloned, &owner, CAROL).await?;
        assert!(is_blocked(&storage.begin_read().await?, &owner, CAROL).await?);
        assert_eq!(storage.cache_metrics().blocklist_entries(), 0);
        assert_eq!(storage.cache_metrics().blocklist_size_bytes(), 0);
        assert_eq!(
            lookup_counts(&storage),
            [
                (BlocklistLookup::Hit, 0),
                (BlocklistLookup::Miss, 1),
                (BlocklistLookup::Bypass, 5),
            ]
        );
        Ok(())
    })
}

#[test]
fn non_blocklist_traits_forward_unchanged() -> TestResult {
    let (_directory, storage) = file_store()?;
    let owner = key(ALICE)?;
    let contact = item(BOB, Some("Bob"), &["Friends"])?;
    let private = PrivateXmlChange {
        namespace: "example:settings",
        name: "settings",
        xml: Some("<settings xmlns='example:settings'/>"),
    };
    block_on(async {
        let mut writer = storage.begin_write().await?;
        writer.create_account(new_account(ALICE, 1)?).await?;
        let sequence = writer
            .push_offline_message(&owner, 42, b"<message/>")
            .await?;
        writer
            .update_private_xml(&owner, &[private], PrivateXmlQuota::default())
            .await?;
        writer
            .put_roster_item(&owner, &contact, RosterQuota::default())
            .await?;
        writer
            .replace_vcard(&owner, "<vCard/>", VCardQuota::default())
            .await?;
        writer.commit().await?;

        let before = storage.begin_read().await?;
        let subscription = RosterSubscription {
            state: SubscriptionState::Both,
            ..Default::default()
        };
        let mut writer = storage.begin_write().await?;
        assert!(
            writer
                .set_roster_subscription(&before, &owner, &contact.jid, subscription)
                .await?
                .is_some()
        );
        writer.commit().await?;

        let reader = storage.begin_read().await?;
        let inner = reader.inner();
        let account = reader.account(&owner).await?;
        assert_eq!(account.as_ref().map(|account| &account.key), Some(&owner));
        assert_eq!(account, inner.account(&owner).await?);
        let messages = reader.offline_messages(&owner).await?;
        assert_eq!(messages[0].sequence, sequence);
        assert_eq!(messages, inner.offline_messages(&owner).await?);
        let stored = reader
            .private_xml(&owner, private.namespace, private.name)
            .await?;
        assert!(stored.is_some());
        assert_eq!(
            stored,
            inner
                .private_xml(&owner, private.namespace, private.name)
                .await?
        );
        assert_eq!(
            reader.roster_subscription(&owner, &contact.jid).await?,
            Some(subscription),
        );
        assert_eq!(
            reader
                .roster_item(&owner, &contact.jid, RosterQuota::default())
                .await?,
            inner
                .roster_item(&owner, &contact.jid, RosterQuota::default())
                .await?,
        );
        let vcard = reader.vcard(&owner).await?;
        assert!(vcard.is_some());
        assert_eq!(vcard, inner.vcard(&owner).await?);
        assert_eq!(storage.cache_metrics().blocklist_entries(), 0);
        Ok(())
    })
}

#[derive(Clone)]
struct OpeningProbe {
    backend: RedbBackend,
    openings: Arc<AtomicUsize>,
}

impl Storage for OpeningProbe {
    type Read = RedbBackendRead;
    type Write = RedbBackendWrite;

    async fn begin_read(&self) -> Result<Self::Read, StorageError> {
        self.backend.begin_read().await
    }

    async fn begin_write(&self) -> Result<Self::Write, StorageError> {
        self.openings.fetch_add(1, Ordering::Relaxed);
        self.backend.begin_write().await
    }

    fn scram_decoy(&self) -> &ScramDecoy {
        self.backend.scram_decoy()
    }
}

struct HeldObserver {
    cache: Arc<BlocklistCache>,
    before: mpsc::Sender<(ThreadId, u64)>,
    after: mpsc::Sender<(ThreadId, u64, bool)>,
    release: mpsc::Receiver<()>,
}

impl CommitObserver for HeldObserver {
    fn before_commit(&mut self) {
        let _ = self
            .before
            .send((thread::current().id(), self.cache.epoch()));
    }

    fn after_commit(&mut self, committed: bool) {
        let _ = self
            .after
            .send((thread::current().id(), self.cache.epoch(), committed));
        let _ = self.release.recv_timeout(TIMEOUT);
    }
}

#[test]
fn generic_writer_admission_outlives_a_cancelled_commit_and_its_observer() -> TestResult {
    let directory = tempfile::tempdir()?;
    let backend = RedbBackend::open(directory.path().join("storage.redb"))?;
    let openings = Arc::new(AtomicUsize::new(0));
    let storage = CachedStorage::wrap(OpeningProbe {
        backend,
        openings: Arc::clone(&openings),
    });
    let cloned = storage.clone();
    let owner = key(ALICE)?;
    let caller = thread::current().id();
    block_on(async {
        let mut writer = storage.begin_write().await?;
        writer.create_account(new_account(ALICE, 1)?).await?;
        writer
            .change_blocklist(&owner, BlockChange::Block(&[jid(BOB)?]))
            .await?;
        let (before, started) = mpsc::channel();
        let (after, completed) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let (before_thread, before_epoch, after_thread, after_epoch, committed);
        {
            let mut commit = pin!(writer.commit_observed(HeldObserver {
                cache: Arc::clone(&storage.blocklists),
                before,
                after,
                release: gate,
            }));
            assert!(poll(commit.as_mut()).is_pending());
            (before_thread, before_epoch) = started.recv_timeout(TIMEOUT)?;
            (after_thread, after_epoch, committed) = completed.recv_timeout(TIMEOUT)?;
        }
        assert!(committed);
        assert_ne!(before_thread, caller);
        assert_eq!(before_thread, after_thread);
        assert_eq!(before_epoch, 1);
        assert_eq!(after_epoch, 2);
        assert_eq!(storage.cache_metrics().blocklist_entries(), 1);

        let mut next = pin!(cloned.begin_write());
        assert!(poll(next.as_mut()).is_pending());
        assert_eq!(openings.load(Ordering::Relaxed), 1);
        release.send(())?;
        drop(next.await?);
        assert_eq!(openings.load(Ordering::Relaxed), 2);
        assert!(is_blocked(&cloned.begin_read().await?, &owner, BOB).await?);
        assert_eq!(
            storage.cache_metrics().blocklist_lookups().next(),
            Some((BlocklistLookup::Hit, 1))
        );
        Ok(())
    })
}
