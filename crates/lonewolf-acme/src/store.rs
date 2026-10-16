// SPDX-License-Identifier: Apache-2.0

use std::fs::{DirBuilder, OpenOptions};
use std::num::NonZeroUsize;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::pin::pin;
use std::sync::{Arc, Weak};
use std::task::Poll;
use std::time::Instant;

use futures_util::future::{Either, poll_fn, select};
use futures_util::task::AtomicWaker;
use graviola::hashing::{Hash, Sha256};
use lonewolf_util::blocking::BlockingExecutor;
use parking_lot::Mutex as PlMutex;
use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, TableDefinition, WriteTransaction,
};
use serde::{Deserialize, Serialize};

use crate::types::{
    StateError, StoredAccount, StoredHost, decode, encode, validate_dns, validate_url,
};

const DIRECTORIES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("acme_directories");
const ACCOUNTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("acme_accounts");
const HOSTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("acme_hosts");

/// State pages contain plaintext secrets and require private filesystem access.
#[derive(Clone)]
pub struct StateStore {
    inner: Arc<Inner>,
}

struct Inner {
    database: Database,
    executor: BlockingExecutor,
    directory_url: String,
    namespace: [u8; 32],
    admission: PlMutex<Admission>,
    #[cfg(test)]
    fault: PlMutex<Fault>,
}

struct Admission {
    accepting: bool,
    uncertain: bool,
    active: usize,
    waiters: Vec<Weak<AtomicWaker>>,
}

struct Operation {
    inner: Arc<Inner>,
}

impl Drop for Operation {
    fn drop(&mut self) {
        let waiters = {
            let mut state = self.inner.admission.lock();
            state.active -= 1;
            if state.active != 0 {
                return;
            }
            std::mem::take(&mut state.waiters)
        };
        for waiter in waiters {
            if let Some(waiter) = waiter.upgrade() {
                waiter.wake();
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountRecord {
    #[serde(deserialize_with = "crate::types::url_string")]
    directory_url: String,
    account: StoredAccount,
}

#[derive(Serialize)]
struct AccountWrite<'a> {
    directory_url: &'a str,
    account: &'a StoredAccount,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostRecord {
    #[serde(deserialize_with = "crate::types::url_string")]
    directory_url: String,
    host: StoredHost,
}

#[derive(Serialize)]
struct HostWrite<'a> {
    directory_url: &'a str,
    host: &'a StoredHost,
}

impl StateStore {
    pub(crate) fn directory_url(&self) -> &str {
        &self.inner.directory_url
    }

    pub async fn open(path: PathBuf, directory_url: String) -> Result<Self, StateError> {
        let executor = BlockingExecutor::new(NonZeroUsize::MIN);
        let shared = executor.clone();
        executor
            .run(move || {
                validate_url(&directory_url)?;
                if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
                    DirBuilder::new()
                        .recursive(true)
                        .mode(0o700)
                        .create(parent)
                        .map_err(|_| StateError::Unavailable)?;
                }
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .mode(0o600)
                    .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                    .open(path)
                    .map_err(|_| StateError::Unavailable)?;
                let metadata = file.metadata().map_err(|_| StateError::Unavailable)?;
                if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
                    return Err(StateError::UnsafePath);
                }
                let database = Database::builder()
                    .create_file(file)
                    .map_err(backend_error)?;
                let mut namespace = [0; 32];
                namespace.copy_from_slice(Sha256::hash(directory_url.as_bytes()).as_ref());
                let transaction = begin_write(&database)?;
                {
                    let mut directories =
                        transaction.open_table(DIRECTORIES).map_err(backend_error)?;
                    let missing = {
                        let existing = directories
                            .get(namespace.as_slice())
                            .map_err(backend_error)?;
                        if let Some(existing) = existing {
                            check_directory(existing.value(), &directory_url)?;
                            false
                        } else {
                            true
                        }
                    };
                    if missing {
                        directories
                            .insert(namespace.as_slice(), directory_url.as_bytes())
                            .map_err(backend_error)?;
                    }
                }
                transaction.open_table(ACCOUNTS).map_err(backend_error)?;
                transaction.open_table(HOSTS).map_err(backend_error)?;
                transaction.commit().map_err(commit_error)?;
                Ok(Self {
                    inner: Arc::new(Inner {
                        database,
                        executor: shared,
                        directory_url,
                        namespace,
                        admission: PlMutex::new(Admission {
                            accepting: true,
                            uncertain: false,
                            active: 0,
                            waiters: Vec::new(),
                        }),
                        #[cfg(test)]
                        fault: PlMutex::new(Fault::None),
                    }),
                })
            })
            .await
    }

    pub async fn account(&self) -> Result<Option<StoredAccount>, StateError> {
        self.run(false, |inner| {
            let transaction = inner.database.begin_read().map_err(backend_error)?;
            let directories = transaction.open_table(DIRECTORIES).map_err(backend_error)?;
            check_directory(
                directories
                    .get(inner.namespace.as_slice())
                    .map_err(backend_error)?
                    .ok_or(StateError::CorruptData)?
                    .value(),
                &inner.directory_url,
            )?;
            let accounts = transaction.open_table(ACCOUNTS).map_err(backend_error)?;
            accounts
                .get(inner.namespace.as_slice())
                .map_err(backend_error)?
                .map(|record| inner.account_record(record.value()))
                .transpose()
        })
        .await
    }

    pub async fn save_account(&self, account: StoredAccount) -> Result<(), StateError> {
        self.run(true, move |inner| {
            account.validate()?;
            let record = encode(&AccountWrite {
                directory_url: &inner.directory_url,
                account: &account,
            })?;
            let transaction = inner.write()?;
            {
                let mut accounts = transaction.open_table(ACCOUNTS).map_err(backend_error)?;
                if let Some(existing) = accounts
                    .get(inner.namespace.as_slice())
                    .map_err(backend_error)?
                {
                    inner.account_record(existing.value())?;
                }
                accounts
                    .insert(inner.namespace.as_slice(), record.as_slice())
                    .map_err(backend_error)?;
            }
            inner.commit(transaction)
        })
        .await
    }

    pub async fn host(&self, dns_name: String) -> Result<Option<StoredHost>, StateError> {
        self.run(false, move |inner| {
            validate_dns(&dns_name)?;
            let key = inner.host_key(&dns_name);
            let transaction = inner.database.begin_read().map_err(backend_error)?;
            let directories = transaction.open_table(DIRECTORIES).map_err(backend_error)?;
            check_directory(
                directories
                    .get(inner.namespace.as_slice())
                    .map_err(backend_error)?
                    .ok_or(StateError::CorruptData)?
                    .value(),
                &inner.directory_url,
            )?;
            let hosts = transaction.open_table(HOSTS).map_err(backend_error)?;
            hosts
                .get(key.as_slice())
                .map_err(backend_error)?
                .map(|record| inner.host_record(record.value(), &dns_name))
                .transpose()
        })
        .await
    }

    /// Replaces the whole record atomically; callers must serialize updates for each host.
    pub async fn save_host(&self, host: StoredHost) -> Result<(), StateError> {
        self.run(true, move |inner| {
            host.validate()?;
            let key = inner.host_key(&host.host.dns_name);
            let record = encode(&HostWrite {
                directory_url: &inner.directory_url,
                host: &host,
            })?;
            let transaction = inner.write()?;
            {
                let mut hosts = transaction.open_table(HOSTS).map_err(backend_error)?;
                if let Some(existing) = hosts.get(key.as_slice()).map_err(backend_error)? {
                    inner.host_record(existing.value(), &host.host.dns_name)?;
                }
                hosts
                    .insert(key.as_slice(), record.as_slice())
                    .map_err(backend_error)?;
            }
            inner.commit(transaction)
        })
        .await
    }

    /// Requires a Compio runtime and permanently stops admission, including on cancellation.
    /// A timeout retains the database lock until its owners and submitted operations finish.
    pub async fn drain(&self, deadline: Instant) -> Result<(), StateError> {
        let waiter = Arc::new(AtomicWaker::new());
        {
            let mut state = self.inner.admission.lock();
            state.accepting = false;
            if state.active == 0 {
                return Ok(());
            }
            state.waiters.retain(|waiter| waiter.strong_count() != 0);
            state.waiters.push(Arc::downgrade(&waiter));
        }
        if Instant::now() >= deadline {
            return Err(StateError::DeadlineElapsed);
        }
        let completed = poll_fn(|context| {
            waiter.register(context.waker());
            if self.inner.admission.lock().active == 0 {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        });
        match select(pin!(compio::time::sleep_until(deadline)), pin!(completed)).await {
            Either::Left(_) => Err(StateError::DeadlineElapsed),
            Either::Right(_) => Ok(()),
        }
    }

    async fn run<T: Send + 'static>(
        &self,
        mutation: bool,
        operation: impl FnOnce(&Inner) -> Result<T, StateError> + Send + 'static,
    ) -> Result<T, StateError> {
        let admitted = {
            let mut state = self.inner.admission.lock();
            if !state.accepting {
                return Err(StateError::Closed);
            }
            if mutation && state.uncertain {
                return Err(StateError::StateUncertain);
            }
            state.active += 1;
            Operation {
                inner: Arc::clone(&self.inner),
            }
        };
        self.inner
            .executor
            .run(move || {
                if mutation && admitted.inner.admission.lock().uncertain {
                    return Err(StateError::StateUncertain);
                }
                operation(&admitted.inner)
            })
            .await
    }
}

impl Inner {
    fn host_key(&self, dns_name: &str) -> Vec<u8> {
        let mut key = Vec::with_capacity(self.namespace.len() + dns_name.len());
        key.extend_from_slice(&self.namespace);
        key.extend_from_slice(dns_name.as_bytes());
        key
    }

    fn account_record(&self, bytes: &[u8]) -> Result<StoredAccount, StateError> {
        let record: AccountRecord = decode(bytes)?;
        check_directory(record.directory_url.as_bytes(), &self.directory_url)?;
        record
            .account
            .validate()
            .map_err(|_| StateError::CorruptData)?;
        Ok(record.account)
    }

    fn host_record(&self, bytes: &[u8], dns_name: &str) -> Result<StoredHost, StateError> {
        let record: HostRecord = decode(bytes)?;
        check_directory(record.directory_url.as_bytes(), &self.directory_url)?;
        record
            .host
            .validate()
            .map_err(|_| StateError::CorruptData)?;
        if record.host.host.dns_name != dns_name {
            return Err(StateError::CorruptData);
        }
        Ok(record.host)
    }

    fn write(&self) -> Result<WriteTransaction, StateError> {
        let transaction = begin_write(&self.database)?;
        {
            let directories = transaction.open_table(DIRECTORIES).map_err(backend_error)?;
            check_directory(
                directories
                    .get(self.namespace.as_slice())
                    .map_err(backend_error)?
                    .ok_or(StateError::CorruptData)?
                    .value(),
                &self.directory_url,
            )?;
        }
        Ok(transaction)
    }

    fn commit(&self, transaction: WriteTransaction) -> Result<(), StateError> {
        #[cfg(test)]
        let fault = std::mem::replace(&mut *self.fault.lock(), Fault::None);
        #[cfg(test)]
        match fault {
            Fault::PreCommit => return Err(StateError::Unavailable),
            Fault::UncertainBefore => {
                self.admission.lock().uncertain = true;
                return Err(StateError::StateUncertain);
            }
            _ => {}
        }
        let result = transaction.commit().map_err(commit_error);
        #[cfg(test)]
        let result = if matches!(fault, Fault::UncertainAfter) && result.is_ok() {
            Err(StateError::StateUncertain)
        } else {
            result
        };
        if result == Err(StateError::StateUncertain) {
            self.admission.lock().uncertain = true;
        }
        result
    }
}

fn check_directory(bytes: &[u8], expected: &str) -> Result<(), StateError> {
    if bytes != expected.as_bytes() {
        return Err(StateError::CorruptData);
    }
    Ok(())
}

fn begin_write(database: &Database) -> Result<WriteTransaction, StateError> {
    let mut transaction = database.begin_write().map_err(backend_error)?;
    transaction
        .set_durability(Durability::Immediate)
        .map_err(backend_error)?;
    Ok(transaction)
}

fn commit_error(error: redb::CommitError) -> StateError {
    if matches!(error, redb::CommitError::TransactionPoisoned) {
        StateError::Unavailable
    } else {
        StateError::StateUncertain
    }
}

fn backend_error(error: impl Into<redb::Error>) -> StateError {
    match error.into() {
        redb::Error::Corrupted(_)
        | redb::Error::TableTypeMismatch { .. }
        | redb::Error::TableIsMultimap(_)
        | redb::Error::TableIsNotMultimap(_)
        | redb::Error::TypeDefinitionChanged { .. }
        | redb::Error::TableDoesNotExist(_) => StateError::CorruptData,
        redb::Error::UpgradeRequired(_) => StateError::UnsupportedData,
        redb::Error::Io(_)
        | redb::Error::DatabaseAlreadyOpen
        | redb::Error::DatabaseClosed
        | redb::Error::PreviousIo
        | redb::Error::LockPoisoned(_) => StateError::Unavailable,
        _ => StateError::Other,
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum Fault {
    None,
    PreCommit,
    UncertainBefore,
    UncertainAfter,
}

#[cfg(test)]
mod tests;
