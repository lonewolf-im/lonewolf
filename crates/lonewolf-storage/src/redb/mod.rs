// SPDX-License-Identifier: Apache-2.0

use std::fs::OpenOptions;
use std::future::Future;
use std::num::NonZeroUsize;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use ::redb::backends::FileBackend;
use ::redb::{
    Database, Durability, ReadTransaction as RedbReadTransaction, ReadableDatabase,
    WriteTransaction as RedbWriteTransaction,
};
use async_lock::{Mutex, MutexGuardArc};
use lonewolf_auth::server::ScramDecoy;
use lonewolf_util::blocking::BlockingExecutor;
use parking_lot::Mutex as PlMutex;

use crate::metrics::{ReadSnapshot, StoreMetrics, StoreOperation};
use crate::storage::{CommitObserver, ReadTransaction, Storage, WriteTransaction};
use crate::{StorageError, StorageErrorKind, account, blocking, offline, private, roster, vcard};

mod error;
mod jid;

pub(crate) use error::{commit_error, storage_error};
pub(crate) use jid::with_canonical_jid;

#[derive(Clone)]
pub struct RedbBackend {
    inner: Arc<Inner>,
}

struct Inner {
    // The shared transaction must drop before the database.
    shared: PlMutex<Option<Shared>>,
    database: Database,
    commits: AtomicU64,
    /// Snapshot openings bypass the read operation limit to avoid stalling callers that hold an ordering lock.
    openings: BlockingExecutor,
    reads: BlockingExecutor,
    writes: BlockingExecutor,
    /// Limits admission so the writer thread can run existing transactions without waiting on redb's writer lock.
    writer: Arc<Mutex<()>>,
    decoy: ScramDecoy,
    metrics: Arc<StoreMetrics>,
}

struct Shared {
    generation: u64,
    transaction: Arc<RedbReadTransaction>,
}

impl Inner {
    fn reuse_snapshot(&self) -> Option<Arc<RedbReadTransaction>> {
        let generation = self.commits.load(Ordering::Acquire);
        self.shared
            .lock()
            .as_ref()
            .filter(|shared| shared.generation == generation)
            .map(|shared| Arc::clone(&shared.transaction))
    }

    fn share_snapshot(&self, transaction: &Arc<RedbReadTransaction>, before: u64, after: u64) {
        let retired = {
            let mut shared = self.shared.lock();
            let generation = self.commits.load(Ordering::Acquire);
            if can_share(
                shared.as_ref().map(|state| state.generation),
                generation,
                before,
                after,
            ) {
                shared.replace(Shared {
                    generation,
                    transaction: Arc::clone(transaction),
                })
            } else {
                None
            }
        };
        drop(retired);
    }

    fn retire_snapshot(&self) -> Option<Shared> {
        let mut shared = self.shared.lock();
        self.commits.fetch_add(1, Ordering::AcqRel);
        shared.take()
    }
}

fn can_share(current: Option<u64>, generation: u64, before: u64, after: u64) -> bool {
    before == after && after == generation && current.is_none_or(|current| current < generation)
}

struct RetireSnapshot<'a>(Option<&'a Inner>);

impl RetireSnapshot<'_> {
    fn finish(mut self) -> Option<Shared> {
        self.0.take().and_then(Inner::retire_snapshot)
    }
}

impl Drop for RetireSnapshot<'_> {
    fn drop(&mut self) {
        if let Some(inner) = self.0.take() {
            drop(inner.retire_snapshot());
        }
    }
}

pub struct RedbBackendRead {
    transaction: Arc<RedbReadTransaction>,
    reads: BlockingExecutor,
}

pub struct RedbBackendWrite {
    inner: Arc<Inner>,
    transaction: Arc<RedbWriteTransaction>,
    writes: BlockingExecutor,
    _writer: MutexGuardArc<()>,
    metrics: Arc<StoreMetrics>,
}

impl RedbBackendRead {
    pub(crate) fn snapshot(&self) -> Arc<RedbReadTransaction> {
        Arc::clone(&self.transaction)
    }
}

impl RedbBackend {
    /// # Errors
    ///
    /// Returns [`StorageErrorKind::CorruptData`] when the existing tables are
    /// inconsistent with each other, or the backend's failure otherwise.
    pub fn new(database: Database) -> Result<Self, StorageError> {
        let decoy = initialize(&database)?;
        Ok(Self {
            inner: Arc::new(Inner {
                shared: PlMutex::new(None),
                database,
                commits: AtomicU64::new(0),
                openings: BlockingExecutor::new(const { NonZeroUsize::new(32).unwrap() }),
                reads: BlockingExecutor::new(const { NonZeroUsize::new(32).unwrap() }),
                writes: BlockingExecutor::new(NonZeroUsize::MIN),
                writer: Arc::new(Mutex::new(())),
                decoy,
                metrics: Arc::new(StoreMetrics::new()),
            }),
        })
    }

    pub fn metrics(&self) -> &StoreMetrics {
        &self.inner.metrics
    }

    async fn open_snapshot(&self) -> Result<Arc<RedbReadTransaction>, StorageError> {
        let inner = Arc::clone(&self.inner);
        let (transaction, before, after) = self
            .inner
            .openings
            .run(move || {
                let before = inner.commits.load(Ordering::Acquire);
                let transaction = inner.database.begin_read().map_err(storage_error)?;
                let after = inner.commits.load(Ordering::Acquire);
                Ok((transaction, before, after))
            })
            .await
            .inspect_err(|error: &StorageError| {
                self.inner
                    .metrics
                    .record_failure(StoreOperation::BeginRead, error.kind());
            })?;
        let transaction = Arc::new(transaction);
        if before == after {
            self.inner.share_snapshot(&transaction, before, after);
        }
        Ok(transaction)
    }

    #[cfg(test)]
    pub(crate) fn forget_shared_snapshot(&self) {
        drop(self.inner.retire_snapshot());
    }

    /// Opens or creates the database file synchronously and initializes its tables.
    ///
    /// New files use mode 0600, subject to the process umask. Existing file
    /// permissions are unchanged, and parent directories must exist.
    ///
    /// # Errors
    ///
    /// Returns [`StorageErrorKind::Unavailable`] if the file cannot be opened or is
    /// already locked. Invalid databases can return [`StorageErrorKind::CorruptData`]
    /// or [`StorageErrorKind::UnsupportedVersion`]. Other backend failures return
    /// [`StorageErrorKind::Other`].
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        options.mode(0o600);
        let file = options.open(path).map_err(storage_error)?;
        let database = Database::builder()
            .create_with_backend(FileBackend::new(file))
            .map_err(storage_error)?;
        Self::new(database)
    }
}

/// Direct database access bypasses the admission limits and can block the caller.
/// An existing shared snapshot hides raw writes until a commit through the storage traits.
impl AsRef<Database> for RedbBackend {
    fn as_ref(&self) -> &Database {
        &self.inner.database
    }
}

fn initialize(database: &Database) -> Result<ScramDecoy, StorageError> {
    let transaction = begin_write(database)?;
    let decoy = account::redb::initialize(&transaction)?;
    roster::redb::initialize(&transaction)?;
    offline::redb::initialize(&transaction)?;
    vcard::redb::initialize(&transaction)?;
    private::redb::initialize(&transaction)?;
    blocking::redb::initialize(&transaction)?;
    transaction.commit().map_err(commit_error)?;
    Ok(decoy)
}

impl Storage for RedbBackend {
    type Read = RedbBackendRead;
    type Write = RedbBackendWrite;

    async fn begin_read(&self) -> Result<RedbBackendRead, StorageError> {
        let (transaction, outcome) = match self.inner.reuse_snapshot() {
            Some(transaction) => (transaction, ReadSnapshot::Reused),
            None => (self.open_snapshot().await?, ReadSnapshot::Opened),
        };
        self.inner.metrics.record_read_snapshot(outcome);
        Ok(RedbBackendRead {
            transaction,
            reads: self.inner.reads.clone(),
        })
    }

    async fn begin_write(&self) -> Result<RedbBackendWrite, StorageError> {
        let started = Instant::now();
        let writer = Arc::clone(&self.inner.writer).lock_arc().await;
        let inner = Arc::clone(&self.inner);
        let transaction = self
            .inner
            .writes
            .run(move || begin_write(&inner.database))
            .await
            .inspect_err(|error| {
                self.inner
                    .metrics
                    .record_failure(StoreOperation::BeginWrite, error.kind());
            })?;
        self.inner
            .metrics
            .write_wait_duration()
            .observe(started.elapsed().as_secs_f64());
        Ok(RedbBackendWrite {
            inner: Arc::clone(&self.inner),
            transaction: Arc::new(transaction),
            writes: self.inner.writes.clone(),
            _writer: writer,
            metrics: Arc::clone(&self.inner.metrics),
        })
    }

    fn scram_decoy(&self) -> &ScramDecoy {
        &self.inner.decoy
    }
}

impl RedbBackendRead {
    pub(crate) fn run<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&RedbReadTransaction) -> T + Send + 'static,
    ) -> impl Future<Output = T> + Send {
        let transaction = Arc::clone(&self.transaction);
        self.reads.run(move || operation(&transaction))
    }
}

impl RedbBackendWrite {
    pub(crate) fn run_with_snapshot<T: Send + 'static, E: From<StorageError> + Send + 'static>(
        &self,
        operation: impl FnOnce(&RedbWriteTransaction, &RedbReadTransaction) -> Result<T, E>
        + Send
        + 'static,
    ) -> impl Future<Output = Result<T, E>> + Send {
        let inner = Arc::clone(&self.inner);
        self.run(move |transaction| {
            let before = inner.database.begin_read().map_err(storage_error)?;
            operation(transaction, &before)
        })
    }

    pub(crate) fn run<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&RedbWriteTransaction) -> T + Send + 'static,
    ) -> impl Future<Output = T> + Send {
        let transaction = Arc::clone(&self.transaction);
        self.writes.run(move || operation(&transaction))
    }
}

impl ReadTransaction for RedbBackendRead {}
impl ReadTransaction for RedbBackendWrite {}

impl WriteTransaction for RedbBackendWrite {
    async fn commit_observed(self, mut observer: impl CommitObserver) -> Result<(), StorageError> {
        let Self {
            transaction,
            writes,
            _writer,
            metrics,
            inner,
        } = self;
        // A canceled operation can still hold the transaction on the writer thread.
        let transaction = Arc::into_inner(transaction).ok_or_else(|| {
            metrics.record_failure(StoreOperation::Commit, StorageErrorKind::Other);
            StorageError::new(StorageErrorKind::Other)
        })?;
        let started = Instant::now();
        let result = writes
            .run(move || {
                observer.before_commit();
                let retirement = RetireSnapshot(Some(&inner));
                let result = transaction.commit().map_err(commit_error);
                // Retire the old snapshot before the observer makes this commit visible.
                let retired = retirement.finish();
                observer.after_commit(result.is_ok());
                drop(retired);
                result
            })
            .await;
        metrics
            .commit_duration()
            .observe(started.elapsed().as_secs_f64());
        result.inspect_err(|error| {
            metrics.record_failure(StoreOperation::Commit, error.kind());
        })
    }
}

pub(crate) fn begin_write(database: &Database) -> Result<RedbWriteTransaction, StorageError> {
    let mut transaction = database.begin_write().map_err(storage_error)?;
    transaction
        .set_durability(Durability::Immediate)
        .map_err(storage_error)?;
    Ok(transaction)
}

#[cfg(test)]
pub(crate) mod tests;
