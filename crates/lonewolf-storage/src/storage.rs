// SPDX-License-Identifier: Apache-2.0

use std::future::Future;

use lonewolf_auth::server::ScramDecoy;

use crate::StorageError;
use crate::account::{AccountReads, AccountWrites};
use crate::offline::{OfflineReads, OfflineWrites};
use crate::roster::{RosterReads, RosterWrites};
use crate::vcard::{VCardReads, VCardWrites};

/// One store, which is one transaction domain.
///
/// Every operation runs on a transaction obtained from [`Self::begin_read`] or
/// [`Self::begin_write`]. A transaction must hold storage work only: awaiting
/// anything else while one is open can stall every other write on the store.
pub trait Storage: Clone + Send + Sync + 'static {
    type Read: ReadTransaction + 'static;
    type Write: WriteTransaction + RosterWrites<Snapshot = Self::Read>;

    /// Opens a read transaction over one consistent snapshot.
    fn begin_read(&self) -> impl Future<Output = Result<Self::Read, StorageError>> + Send;

    /// Opens a write transaction. A store admits one at a time unless it can keep the
    /// reads of concurrent write transactions stable, as [`WriteTransaction`] requires.
    fn begin_write(&self) -> impl Future<Output = Result<Self::Write, StorageError>> + Send;

    /// The per-store secret that keeps authentication timing equal for absent accounts.
    fn scram_decoy(&self) -> &ScramDecoy;
}

pub trait ReadTransaction:
    AccountReads + OfflineReads + RosterReads + VCardReads + Send + Sync
{
}

/// Writes commit atomically, and values read stay stable until commit or abort.
/// The store must serialize writers or lock all values read; read-committed isolation is insufficient.
///
/// Dropping the transaction without committing aborts every write in it.
pub trait WriteTransaction:
    ReadTransaction + AccountWrites + OfflineWrites + RosterWrites + VCardWrites
{
    /// Persists every write made through this transaction.
    ///
    /// # Errors
    ///
    /// [`crate::StorageErrorKind::CommitUnknown`] means the writes may have landed.
    fn commit(self) -> impl Future<Output = Result<(), StorageError>> + Send;
}
