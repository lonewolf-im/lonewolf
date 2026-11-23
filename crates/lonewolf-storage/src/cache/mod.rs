// SPDX-License-Identifier: Apache-2.0

mod blocklist;
mod forward;
mod metrics;

use std::future::Future;
use std::path::Path;
use std::sync::Arc;

use ::redb::Database;
use async_lock::{Mutex, MutexGuardArc};
use lonewolf_auth::server::ScramDecoy;
use lonewolf_xmpp::jid::JidRef;

use crate::account::AccountKey;
use crate::blocking::{BlockChange, BlockDelta, BlockError, BlockingReads, BlockingWrites};
use crate::metrics::StoreMetrics;
use crate::roster::RosterJid;
use crate::{
    CommitObserver, ReadTransaction, RedbBackend, Storage, StorageError, WriteTransaction,
};

use blocklist::{BlocklistCache, BlocklistCommit, Lookup, Rules, Stamp, rules_match};

pub use metrics::{BlocklistFill, BlocklistLookup, BlocklistUpdate, CacheMetrics};

#[derive(Clone)]
pub struct CachedStorage<B> {
    backend: B,
    blocklists: Arc<BlocklistCache>,
    writer: Option<Arc<Mutex<()>>>,
}

pub struct CachedRead<R> {
    inner: R,
    blocklists: Arc<BlocklistCache>,
    stamp: Option<Stamp>,
}

pub struct CachedWrite<W> {
    inner: W,
    blocklists: Arc<BlocklistCache>,
    changes: Vec<(AccountKey, Option<Rules>)>,
    writer: Option<MutexGuardArc<()>>,
}

impl<B: Storage> CachedStorage<B> {
    /// Route all local writes for this backend through this single wrapper and its clones.
    /// Use the wrapper even when the caller holds a cloned or raw backend handle.
    pub fn wrap(backend: B) -> Self {
        Self {
            backend,
            blocklists: Arc::new(BlocklistCache::new()),
            writer: Some(Arc::new(Mutex::new(()))),
        }
    }

    pub fn cache_metrics(&self) -> &CacheMetrics {
        self.blocklists.metrics()
    }

    /// Drops the owner's cached rules when a remote commit reports a change.
    pub fn invalidate_blocklist(&self, owner: &AccountKey) {
        self.blocklists.invalidate(owner.as_str());
    }
}

impl CachedStorage<RedbBackend> {
    /// Initializes the tables in an open database.
    ///
    /// # Errors
    ///
    /// Returns [`crate::StorageErrorKind::CorruptData`] for inconsistent tables.
    pub fn new(database: Database) -> Result<Self, StorageError> {
        RedbBackend::new(database).map(Self::from_redb)
    }

    /// Opens or creates a database and initializes its tables synchronously.
    /// New files use mode 0600 subject to the umask. Existing permissions stay the same.
    /// Parent directories must exist.
    ///
    /// # Errors
    ///
    /// Returns [`crate::StorageErrorKind::Unavailable`] for an inaccessible or locked file.
    /// Invalid databases can return [`crate::StorageErrorKind::CorruptData`] or
    /// [`crate::StorageErrorKind::UnsupportedVersion`].
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        RedbBackend::open(path).map(Self::from_redb)
    }

    fn from_redb(backend: RedbBackend) -> Self {
        Self {
            backend,
            blocklists: Arc::new(BlocklistCache::new()),
            writer: None,
        }
    }

    pub fn metrics(&self) -> &StoreMetrics {
        self.backend.metrics()
    }
}

/// Direct database access can block the caller and permanently disables blocklist caching.
impl AsRef<Database> for CachedStorage<RedbBackend> {
    fn as_ref(&self) -> &Database {
        self.blocklists.disable();
        self.backend.as_ref()
    }
}

impl<R> CachedRead<R> {
    pub(crate) fn inner(&self) -> &R {
        &self.inner
    }
}

#[cfg(test)]
impl<W> CachedWrite<W> {
    pub(crate) fn inner(&self) -> &W {
        &self.inner
    }
}

impl<B: Storage> Storage for CachedStorage<B> {
    type Read = CachedRead<B::Read>;
    type Write = CachedWrite<B::Write>;

    async fn begin_read(&self) -> Result<Self::Read, StorageError> {
        let before = self.blocklists.epoch();
        let inner = self.backend.begin_read().await?;
        let stamp = self.blocklists.stamp(before);
        Ok(CachedRead {
            inner,
            blocklists: Arc::clone(&self.blocklists),
            stamp,
        })
    }

    async fn begin_write(&self) -> Result<Self::Write, StorageError> {
        let writer = match &self.writer {
            Some(writer) => Some(writer.lock_arc().await),
            None => None,
        };
        let inner = self.backend.begin_write().await?;
        Ok(CachedWrite {
            inner,
            blocklists: Arc::clone(&self.blocklists),
            changes: Vec::new(),
            writer,
        })
    }

    fn scram_decoy(&self) -> &ScramDecoy {
        self.backend.scram_decoy()
    }
}

impl<R: ReadTransaction> ReadTransaction for CachedRead<R> {}
impl<W: ReadTransaction> ReadTransaction for CachedWrite<W> {}

impl<W: WriteTransaction> WriteTransaction for CachedWrite<W> {
    async fn commit_observed(self, observer: impl CommitObserver) -> Result<(), StorageError> {
        let Self {
            inner,
            blocklists,
            changes,
            writer,
        } = self;
        if changes.is_empty() && writer.is_none() {
            return inner.commit_observed(observer).await;
        }
        let blocklists = (!changes.is_empty()).then(|| blocklists.commit_observer(changes));
        inner
            .commit_observed(Observers {
                blocklists,
                caller: observer,
                _writer: writer,
            })
            .await
    }
}

struct Observers<O> {
    blocklists: Option<BlocklistCommit>,
    caller: O,
    _writer: Option<MutexGuardArc<()>>,
}

impl<O: CommitObserver> CommitObserver for Observers<O> {
    fn before_commit(&mut self) {
        if let Some(observer) = &mut self.blocklists {
            observer.before_commit();
        }
        self.caller.before_commit();
    }

    fn after_commit(&mut self, committed: bool) {
        if let Some(observer) = &mut self.blocklists {
            observer.after_commit(committed);
        }
        self.caller.after_commit(committed);
    }
}

impl<R: BlockingReads + Sync> BlockingReads for CachedRead<R> {
    async fn blocklist(&self, owner: &AccountKey) -> Result<Vec<RosterJid>, BlockError> {
        match self.blocklists.lookup(owner.as_str(), self.stamp) {
            Lookup::Hit(rules) => Ok(rules.to_vec()),
            Lookup::Miss(stamp) => {
                let rules = canonical_rules(self.inner.blocklist(owner).await?);
                self.blocklists
                    .fill(owner.as_str(), stamp, Rules::from(rules.as_slice()));
                Ok(rules)
            }
            Lookup::Bypass => self.inner.blocklist(owner).await,
        }
    }

    async fn is_blocked(&self, owner: &AccountKey, peer: JidRef<'_>) -> Result<bool, BlockError> {
        match self.blocklists.lookup(owner.as_str(), self.stamp) {
            Lookup::Hit(rules) => Ok(rules_match(&rules, peer)),
            Lookup::Miss(stamp) => {
                let rules = Rules::from(canonical_rules(self.inner.blocklist(owner).await?));
                let matched = rules_match(&rules, peer);
                self.blocklists.fill(owner.as_str(), stamp, rules);
                Ok(matched)
            }
            Lookup::Bypass => self.inner.is_blocked(owner, peer).await,
        }
    }
}

impl<W: BlockingReads> BlockingReads for CachedWrite<W> {
    fn blocklist(
        &self,
        owner: &AccountKey,
    ) -> impl Future<Output = Result<Vec<RosterJid>, BlockError>> + Send {
        self.inner.blocklist(owner)
    }

    fn is_blocked(
        &self,
        owner: &AccountKey,
        peer: JidRef<'_>,
    ) -> impl Future<Output = Result<bool, BlockError>> + Send {
        self.inner.is_blocked(owner, peer)
    }
}

impl<W: BlockingWrites + Send> BlockingWrites for CachedWrite<W> {
    async fn change_blocklist(
        &mut self,
        owner: &AccountKey,
        change: BlockChange<'_>,
    ) -> Result<BlockDelta, BlockError> {
        let pending = self.changes.len();
        self.changes.push((owner.clone(), None));
        let delta = self.inner.change_blocklist(owner, change).await?;
        let rules = canonical_rules(delta.after_rules().cloned().collect());
        self.changes[pending].1 = Some(rules.into());
        Ok(delta)
    }

    async fn delete_blocklist(&mut self, owner: &AccountKey) -> Result<(), StorageError> {
        self.changes.push((owner.clone(), None));
        self.inner.delete_blocklist(owner).await
    }
}

fn canonical_rules(mut rules: Vec<RosterJid>) -> Vec<RosterJid> {
    rules.sort_unstable();
    rules.dedup();
    rules
}

#[cfg(test)]
mod tests;
