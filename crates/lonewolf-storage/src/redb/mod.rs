// SPDX-License-Identifier: Apache-2.0

use std::fs::OpenOptions;
use std::num::NonZeroUsize;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;

use ::redb::{Database, Durability, TableDefinition, WriteTransaction};

use lonewolf_util::blocking::BlockingExecutor;

use crate::StorageError;

mod error;

pub(crate) use error::{commit_error, storage_error};

pub(crate) const METADATA: TableDefinition<&str, u32> = TableDefinition::new("lonewolf_metadata");

/// Clones share limits of 32 submitted reads and one submitted write.
#[derive(Clone)]
pub struct RedbDatabase {
    database: Arc<Database>,
    reads: BlockingExecutor,
    writes: BlockingExecutor,
}

impl RedbDatabase {
    pub fn new(database: Database) -> Self {
        Self {
            database: Arc::new(database),
            reads: BlockingExecutor::new(const { NonZeroUsize::new(32).unwrap() }),
            writes: BlockingExecutor::new(NonZeroUsize::MIN),
        }
    }

    /// Opens or creates the database synchronously.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        options.mode(0o600);
        let file = options.open(path).map_err(storage_error)?;
        Database::builder()
            .create_file(file)
            .map(Self::new)
            .map_err(storage_error)
    }

    pub(crate) async fn read<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&Database) -> T + Send + 'static,
    ) -> T {
        let database = Arc::clone(&self.database);
        self.reads.run(move || operation(&database)).await
    }

    pub(crate) async fn write<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&Database) -> T + Send + 'static,
    ) -> T {
        let database = Arc::clone(&self.database);
        self.writes.run(move || operation(&database)).await
    }
}

/// Direct database access bypasses admission limits and can block the caller.
impl AsRef<Database> for RedbDatabase {
    fn as_ref(&self) -> &Database {
        &self.database
    }
}

pub(crate) fn begin_write(database: &Database) -> Result<WriteTransaction, StorageError> {
    let mut transaction = database.begin_write().map_err(storage_error)?;
    transaction
        .set_durability(Durability::Immediate)
        .map_err(storage_error)?;
    Ok(transaction)
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::mpsc;
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    use ::redb::{Database, backends::InMemoryBackend};
    use futures_executor::block_on;

    use super::RedbDatabase;

    type TestResult = Result<(), Box<dyn Error>>;
    const TIMEOUT: Duration = Duration::from_secs(5);

    #[test]
    fn cloned_databases_share_one_writer_without_blocking_reads() -> TestResult {
        let database = database()?;
        let cloned = database.clone();
        let (entered, started) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let mut first = Box::pin(database.write(move |_| {
            let _ = entered.send(());
            gate.recv_timeout(TIMEOUT)
        }));
        assert!(poll(first.as_mut()).is_pending());
        started.recv_timeout(TIMEOUT)?;

        let (entered, started) = mpsc::channel();
        let mut waiting = Box::pin(cloned.write(move |_| {
            let _ = entered.send(());
        }));
        assert!(poll(waiting.as_mut()).is_pending());
        assert_eq!(block_on(cloned.read(|_| 42)), 42);
        drop(waiting);
        assert!(matches!(
            started.try_recv(),
            Err(mpsc::TryRecvError::Disconnected)
        ));

        release.send(())?;
        block_on(first)?;
        assert_eq!(block_on(cloned.write(|_| 42)), 42);
        Ok(())
    }

    #[test]
    fn full_read_capacity_does_not_block_a_writer() -> TestResult {
        let database = database()?;
        let mut reads = Vec::with_capacity(32);
        for _ in 0..32 {
            let (entered, started) = mpsc::channel();
            let (release, gate) = mpsc::channel();
            let mut read = Box::pin(database.read(move |_| {
                let _ = entered.send(());
                gate.recv_timeout(TIMEOUT)
            }));
            assert!(poll(read.as_mut()).is_pending());
            started.recv_timeout(TIMEOUT)?;
            reads.push((read, release));
        }

        let (entered, started) = mpsc::channel();
        let mut waiting = Box::pin(database.read(move |_| {
            let _ = entered.send(());
        }));
        assert!(poll(waiting.as_mut()).is_pending());
        assert_eq!(block_on(database.write(|_| 42)), 42);
        drop(waiting);
        assert!(matches!(
            started.try_recv(),
            Err(mpsc::TryRecvError::Disconnected)
        ));

        for (read, release) in reads {
            release.send(())?;
            block_on(read)?;
        }
        assert_eq!(block_on(database.read(|_| 42)), 42);
        Ok(())
    }

    fn database() -> Result<RedbDatabase, ::redb::DatabaseError> {
        Database::builder()
            .set_cache_size(1024 * 1024)
            .create_with_backend(InMemoryBackend::new())
            .map(RedbDatabase::new)
    }

    fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }
}
