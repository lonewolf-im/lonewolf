// SPDX-License-Identifier: Apache-2.0

use std::fs::OpenOptions;
use std::future::Future;
use std::num::NonZeroUsize;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use ::redb::{
    Database, Durability, ReadTransaction as RedbReadTransaction, ReadableDatabase,
    WriteTransaction as RedbWriteTransaction,
};
use async_lock::{Mutex, MutexGuardArc};
use lonewolf_auth::server::ScramDecoy;
use lonewolf_util::blocking::BlockingExecutor;

use crate::metrics::{StoreMetrics, StoreOperation};
use crate::storage::{ReadTransaction, Storage, WriteTransaction};
use crate::{StorageError, StorageErrorKind, account, offline, roster};

mod error;
mod jid;

pub(crate) use error::{commit_error, storage_error};
pub(crate) use jid::with_canonical_jid;

/// A redb database as one transaction domain.
///
/// Clones share the database, its admission limits of 32 submitted reads and one
/// open write transaction, and the SCRAM decoy secret.
#[derive(Clone)]
pub struct RedbStorage {
    inner: Arc<Inner>,
}

struct Inner {
    database: Database,
    reads: BlockingExecutor,
    writes: BlockingExecutor,
    /// Admits one write transaction at a time ahead of the writer thread, so that
    /// thread never blocks inside redb's own writer lock while a handle is open.
    writer: Arc<Mutex<()>>,
    decoy: ScramDecoy,
    metrics: Arc<StoreMetrics>,
}

/// One consistent snapshot; every operation runs on the read executor.
pub struct RedbRead {
    transaction: Arc<RedbReadTransaction>,
    reads: BlockingExecutor,
}

/// The store's open write transaction; operations and the commit run on the writer thread.
/// Being the only one open keeps everything it reads stable until it commits.
pub struct RedbWrite {
    inner: Arc<Inner>,
    transaction: Arc<RedbWriteTransaction>,
    writes: BlockingExecutor,
    _writer: MutexGuardArc<()>,
    metrics: Arc<StoreMetrics>,
}

impl RedbRead {
    pub(crate) fn snapshot(&self) -> Arc<RedbReadTransaction> {
        Arc::clone(&self.transaction)
    }
}

impl RedbStorage {
    /// Wraps an open database and initializes every table the current code needs.
    ///
    /// # Errors
    ///
    /// Returns [`StorageErrorKind::CorruptData`] when the existing tables are
    /// inconsistent with each other, or the backend's failure otherwise.
    pub fn new(database: Database) -> Result<Self, StorageError> {
        let decoy = initialize(&database)?;
        Ok(Self {
            inner: Arc::new(Inner {
                database,
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
            .create_file(file)
            .map_err(storage_error)?;
        Self::new(database)
    }
}

/// Direct database access bypasses the admission limits and can block the caller.
impl AsRef<Database> for RedbStorage {
    fn as_ref(&self) -> &Database {
        &self.inner.database
    }
}

fn initialize(database: &Database) -> Result<ScramDecoy, StorageError> {
    let transaction = begin_write(database)?;
    let decoy = account::redb::initialize(&transaction)?;
    roster::redb::initialize(&transaction)?;
    offline::redb::initialize(&transaction)?;
    transaction.commit().map_err(commit_error)?;
    Ok(decoy)
}

impl Storage for RedbStorage {
    type Read = RedbRead;
    type Write = RedbWrite;

    async fn begin_read(&self) -> Result<RedbRead, StorageError> {
        let inner = Arc::clone(&self.inner);
        let transaction = self
            .inner
            .reads
            .run(move || inner.database.begin_read().map_err(storage_error))
            .await
            .inspect_err(|error| {
                self.inner
                    .metrics
                    .record_failure(StoreOperation::BeginRead, error.kind());
            })?;
        Ok(RedbRead {
            transaction: Arc::new(transaction),
            reads: self.inner.reads.clone(),
        })
    }

    async fn begin_write(&self) -> Result<RedbWrite, StorageError> {
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
        Ok(RedbWrite {
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

impl RedbRead {
    pub(crate) fn run<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&RedbReadTransaction) -> T + Send + 'static,
    ) -> impl Future<Output = T> + Send {
        let transaction = Arc::clone(&self.transaction);
        self.reads.run(move || operation(&transaction))
    }
}

impl RedbWrite {
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

impl ReadTransaction for RedbRead {}
impl ReadTransaction for RedbWrite {}

impl WriteTransaction for RedbWrite {
    async fn commit(self) -> Result<(), StorageError> {
        let Self {
            transaction,
            writes,
            _writer,
            metrics,
            inner: _,
        } = self;
        // An operation future dropped before it finished may still hold the
        // transaction on the writer thread; committing around it is unsafe.
        let transaction = Arc::into_inner(transaction).ok_or_else(|| {
            metrics.record_failure(StoreOperation::Commit, StorageErrorKind::Other);
            StorageError::new(StorageErrorKind::Other)
        })?;
        let started = Instant::now();
        let result = writes
            .run(move || transaction.commit().map_err(commit_error))
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
