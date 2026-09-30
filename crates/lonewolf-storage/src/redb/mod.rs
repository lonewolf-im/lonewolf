// SPDX-License-Identifier: Apache-2.0

use std::fs::OpenOptions;
use std::future::Future;
use std::num::NonZeroUsize;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;

use ::redb::{
    Database, Durability, ReadTransaction as RedbReadTransaction, ReadableDatabase,
    WriteTransaction as RedbWriteTransaction,
};
use async_lock::{Mutex, MutexGuardArc};
use lonewolf_auth::server::ScramDecoy;
use lonewolf_util::blocking::BlockingExecutor;

use crate::storage::{ReadTransaction, Storage, WriteTransaction};
use crate::{StorageError, StorageErrorKind, account, roster};

mod error;

pub(crate) use error::{commit_error, storage_error};

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
}

/// One consistent snapshot; every operation runs on the read executor.
pub struct RedbRead {
    transaction: Arc<RedbReadTransaction>,
    reads: BlockingExecutor,
}

/// The store's open write transaction; operations and the commit run on the writer thread.
pub struct RedbWrite {
    transaction: Arc<RedbWriteTransaction>,
    writes: BlockingExecutor,
    _writer: MutexGuardArc<()>,
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
            }),
        })
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
            .await?;
        Ok(RedbRead {
            transaction: Arc::new(transaction),
            reads: self.inner.reads.clone(),
        })
    }

    async fn begin_write(&self) -> Result<RedbWrite, StorageError> {
        let writer = Arc::clone(&self.inner.writer).lock_arc().await;
        let inner = Arc::clone(&self.inner);
        let transaction = self
            .inner
            .writes
            .run(move || begin_write(&inner.database))
            .await?;
        Ok(RedbWrite {
            transaction: Arc::new(transaction),
            writes: self.inner.writes.clone(),
            _writer: writer,
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
        } = self;
        // An operation future dropped before it finished may still hold the
        // transaction on the writer thread; committing around it is unsafe.
        let transaction = Arc::into_inner(transaction)
            .ok_or_else(|| StorageError::new(StorageErrorKind::Other))?;
        writes
            .run(move || transaction.commit().map_err(commit_error))
            .await
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
