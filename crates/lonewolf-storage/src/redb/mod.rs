// SPDX-License-Identifier: Apache-2.0

use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use ::redb::{Database, Durability, TableDefinition, WriteTransaction};

use crate::StorageError;

mod blocking;
mod error;

pub(crate) use blocking::run as run_blocking;
pub(crate) use error::{commit_error, storage_error};

pub(crate) const METADATA: TableDefinition<&str, u32> = TableDefinition::new("lonewolf_metadata");

pub(crate) fn open_database(path: impl AsRef<Path>) -> Result<Database, StorageError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(path).map_err(storage_error)?;
    Database::builder().create_file(file).map_err(storage_error)
}

pub(crate) fn begin_write(database: &Database) -> Result<WriteTransaction, StorageError> {
    let mut transaction = database.begin_write().map_err(storage_error)?;
    transaction
        .set_durability(Durability::Immediate)
        .map_err(storage_error)?;
    Ok(transaction)
}
