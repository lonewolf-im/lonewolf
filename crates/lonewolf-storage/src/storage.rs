// SPDX-License-Identifier: Apache-2.0

use std::future::Future;

use lonewolf_auth::server::ScramDecoy;

use crate::StorageError;
use crate::account::{AccountReads, AccountWrites};
use crate::roster::{RosterReads, RosterWrites};

/// One store, which is one transaction domain.
///
/// Every operation runs on a transaction obtained from [`Self::begin_read`] or
/// [`Self::begin_write`]. A transaction must hold storage work only: awaiting
/// anything else while one is open can stall every other write on the store.
pub trait Storage: Clone + Send + Sync + 'static {
    type Read: ReadTransaction;
    type Write: WriteTransaction;

    /// Opens a read transaction over one consistent snapshot.
    fn begin_read(&self) -> impl Future<Output = Result<Self::Read, StorageError>> + Send;

    /// Opens a write transaction. A store admits one at a time unless it can keep the
    /// reads of concurrent write transactions stable, as [`WriteTransaction`] requires.
    fn begin_write(&self) -> impl Future<Output = Result<Self::Write, StorageError>> + Send;

    /// The per-store secret that keeps authentication timing equal for absent accounts.
    fn scram_decoy(&self) -> &ScramDecoy;
}

/// The operations available on one consistent snapshot.
pub trait ReadTransaction: AccountReads + RosterReads + Send + Sync {}

/// The operations available inside one atomic write.
///
/// Every value read through the transaction stays as read until the transaction
/// commits or aborts: no other transaction changes it in between, so a flow that reads,
/// decides, and writes never loses an update. A store meets this by admitting one write
/// transaction at a time or by locking what a transaction reads. Read-committed
/// isolation without locks does not meet it.
///
/// Dropping the transaction without committing aborts every write in it.
pub trait WriteTransaction: ReadTransaction + AccountWrites + RosterWrites {
    /// Persists every write made through this transaction.
    ///
    /// # Errors
    ///
    /// [`crate::StorageErrorKind::CommitUnknown`] means the writes may have landed.
    fn commit(self) -> impl Future<Output = Result<(), StorageError>> + Send;
}
