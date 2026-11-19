// SPDX-License-Identifier: Apache-2.0

use std::future::Future;

use lonewolf_auth::server::ScramDecoy;

use crate::StorageError;
use crate::account::{AccountReads, AccountWrites};
use crate::blocking::{BlockingReads, BlockingWrites};
use crate::offline::{OfflineReads, OfflineWrites};
use crate::private::{PrivateXmlReads, PrivateXmlWrites};
use crate::roster::{RosterReads, RosterWrites};
use crate::vcard::{VCardReads, VCardWrites};

/// Await only storage work while a transaction is open to avoid stalling other writes.
pub trait Storage: Clone + Send + Sync + 'static {
    type Read: ReadTransaction + 'static;
    type Write: WriteTransaction + RosterWrites<Snapshot = Self::Read>;

    /// Reads use one consistent snapshot.
    fn begin_read(&self) -> impl Future<Output = Result<Self::Read, StorageError>> + Send;

    fn begin_write(&self) -> impl Future<Output = Result<Self::Write, StorageError>> + Send;

    /// The per-store secret that keeps authentication timing equal for absent accounts.
    fn scram_decoy(&self) -> &ScramDecoy;
}

pub trait ReadTransaction:
    AccountReads
    + BlockingReads
    + OfflineReads
    + PrivateXmlReads
    + RosterReads
    + VCardReads
    + Send
    + Sync
{
}

/// Writes commit atomically and reads stay stable until commit or abort.
/// Dropping an uncommitted transaction discards all its writes.
pub trait WriteTransaction:
    ReadTransaction
    + AccountWrites
    + BlockingWrites
    + OfflineWrites
    + PrivateXmlWrites
    + RosterWrites
    + VCardWrites
{
    /// # Errors
    ///
    /// [`crate::StorageErrorKind::CommitUnknown`] means the writes may have landed.
    fn commit(self) -> impl Future<Output = Result<(), StorageError>> + Send;
}
