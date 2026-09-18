// SPDX-License-Identifier: Apache-2.0

use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;

use ::redb::{Database, Durability, TableDefinition, WriteTransaction};

use crate::StorageError;

mod blocking;
mod error;

use blocking::Blocking;
pub(crate) use error::{commit_error, storage_error};

pub(crate) const METADATA: TableDefinition<&str, u32> = TableDefinition::new("lonewolf_metadata");

/// Clones share limits of 32 submitted reads and one submitted write.
#[derive(Clone)]
pub struct RedbDatabase {
    database: Arc<Database>,
    blocking: Blocking,
}

impl RedbDatabase {
    pub fn new(database: Database) -> Self {
        Self {
            database: Arc::new(database),
            blocking: Blocking::new(),
        }
    }

    /// Opens or creates the database synchronously.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
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
        self.blocking.read(move || operation(&database)).await
    }

    pub(crate) async fn write<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&Database) -> T + Send + 'static,
    ) -> T {
        let database = Arc::clone(&self.database);
        self.blocking.write(move || operation(&database)).await
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
