// SPDX-License-Identifier: Apache-2.0

//! Stores each account and all its verifiers in one versioned redb record.

use std::future::Future;
use std::num::{NonZeroU32, NonZeroUsize};
use std::ops::Bound;

use ::redb::{
    ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle, WriteTransaction,
};
use lonewolf_auth::scram::{
    SCRAM_POLICY_ITERATIONS, ScramCredentials, ScramHash, ScramSha1Verifier, ScramSha256Verifier,
    ScramVerifier, ScramVerifierData,
};
use lonewolf_auth::server::ScramDecoy;
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_xmpp::jid::{Jid, JidError, MAX_PART_LEN};
use zeroize::Zeroizing;

use crate::account::{Account, AccountError, AccountKey, AccountReads, AccountWrites, NewAccount};
use crate::redb::{RedbRead, RedbWrite, storage_error};
use crate::{StorageError, StorageErrorKind};

pub(crate) const ACCOUNTS: TableDefinition<&str, &[u8]> = TableDefinition::new("lonewolf_accounts");
pub(crate) const DECOY_SECRET: TableDefinition<&str, &[u8]> =
    TableDefinition::new("lonewolf_scram_decoy");
pub(crate) const DECOY_SECRET_KEY: &str = "secret";
const RECORD_VERSION: u8 = 1;
const SHA1: u8 = 1;
const SHA256: u8 = 2;
const MAX_RECORD_BYTES: usize = 2 + (16 + 4 + 20 * 2) + (16 + 4 + 32 * 2);

/// Creates the account tables and loads or creates the SCRAM decoy secret.
///
/// # Errors
///
/// Returns [`StorageErrorKind::CorruptData`] for incomplete account or decoy state.
pub(crate) fn initialize(transaction: &WriteTransaction) -> Result<ScramDecoy, StorageError> {
    let mut accounts_table_exists = false;
    let mut decoy_table_exists = false;
    for table in transaction.list_tables().map_err(storage_error)? {
        accounts_table_exists |= table.name() == ACCOUNTS.name();
        decoy_table_exists |= table.name() == DECOY_SECRET.name();
    }
    if decoy_table_exists != accounts_table_exists {
        return Err(StorageError::new(StorageErrorKind::CorruptData));
    }
    let fresh = !accounts_table_exists;
    let mut secret = Zeroizing::new([0; 32]);
    transaction.open_table(ACCOUNTS).map_err(storage_error)?;
    let mut table = transaction
        .open_table(DECOY_SECRET)
        .map_err(storage_error)?;
    let existing = table.get(DECOY_SECRET_KEY).map_err(storage_error)?;
    match existing.as_ref() {
        Some(stored) => {
            if stored.value().len() != secret.len() || table.len().map_err(storage_error)? != 1 {
                return Err(StorageError::new(StorageErrorKind::CorruptData));
            }
            secret.copy_from_slice(stored.value());
        }
        None if !fresh => {
            return Err(StorageError::new(StorageErrorKind::CorruptData));
        }
        None => {}
    }
    let missing = existing.is_none();
    drop(existing);
    if missing {
        getrandom::fill(secret.as_mut())
            .map_err(|error| StorageError::with_source(StorageErrorKind::Other, error))?;
        table
            .insert(DECOY_SECRET_KEY, &secret[..])
            .map_err(storage_error)?;
    }
    Ok(ScramDecoy::from_secret(*secret))
}

macro_rules! account_reads {
    ($handle:ty) => {
        impl AccountReads for $handle {
            fn account(
                &self,
                key: &AccountKey,
            ) -> impl Future<Output = Result<Option<Account>, AccountError>> + Send {
                let key = key.clone();
                self.run(move |transaction| {
                    let table = transaction.open_table(ACCOUNTS).map_err(storage_error)?;
                    read_account(&table, key)
                })
            }

            fn scram(
                &self,
                key: &AccountKey,
                hash: ScramHash,
            ) -> impl Future<Output = Result<Option<ScramVerifier>, AccountError>> + Send {
                let key = key.clone();
                self.run(move |transaction| {
                    let table = transaction.open_table(ACCOUNTS).map_err(storage_error)?;
                    read_scram(&table, &key, hash)
                })
            }

            fn accounts_after(
                &self,
                after: Option<&AccountKey>,
                limit: NonZeroUsize,
            ) -> impl Future<Output = Result<Vec<Account>, AccountError>> + Send {
                let after = after.cloned();
                self.run(move |transaction| {
                    let table = transaction.open_table(ACCOUNTS).map_err(storage_error)?;
                    list_accounts(&table, after.as_ref(), limit)
                })
            }
        }
    };
}

account_reads!(RedbRead);
account_reads!(RedbWrite);

impl AccountWrites for RedbWrite {
    fn create_account(
        &mut self,
        account: NewAccount,
    ) -> impl Future<Output = Result<(), AccountError>> + Send {
        self.run(move |transaction| create(transaction, account))
    }

    fn delete_account(
        &mut self,
        key: &AccountKey,
    ) -> impl Future<Output = Result<(), AccountError>> + Send {
        let key = key.clone();
        self.run(move |transaction| delete(transaction, &key))
    }

    fn replace_credentials(
        &mut self,
        key: &AccountKey,
        credentials: ScramCredentials,
    ) -> impl Future<Output = Result<(), AccountError>> + Send {
        let key = key.clone();
        self.run(move |transaction| replace_credentials(transaction, &key, credentials))
    }
}

fn read_account<T: ReadableTable<&'static str, &'static [u8]>>(
    table: &T,
    key: AccountKey,
) -> Result<Option<Account>, AccountError> {
    let Some(record) = table.get(key.as_str()).map_err(storage_error)? else {
        return Ok(None);
    };
    decode_credentials(record.value())?;
    Ok(Some(Account { key }))
}

fn read_scram<T: ReadableTable<&'static str, &'static [u8]>>(
    table: &T,
    key: &AccountKey,
    hash: ScramHash,
) -> Result<Option<ScramVerifier>, AccountError> {
    let Some(record) = table.get(key.as_str()).map_err(storage_error)? else {
        return Ok(None);
    };
    let credentials = decode_credentials(record.value())?;
    Ok(match hash {
        ScramHash::Sha1 => credentials.sha1.map(ScramVerifier::Sha1),
        ScramHash::Sha256 => credentials.sha256.map(ScramVerifier::Sha256),
    })
}

fn list_accounts<T: ReadableTable<&'static str, &'static [u8]>>(
    table: &T,
    after: Option<&AccountKey>,
    limit: NonZeroUsize,
) -> Result<Vec<Account>, AccountError> {
    let start = after.map_or(Bound::Unbounded, |key| Bound::Excluded(key.as_str()));
    let mut accounts = Vec::new();
    for entry in table
        .range::<&str>((start, Bound::Unbounded))
        .map_err(storage_error)?
        .take(limit.get())
    {
        let (key, record) = entry.map_err(storage_error)?;
        decode_credentials(record.value())?;
        accounts.push(Account {
            key: decode_account_key(key.value())?,
        });
    }
    Ok(accounts)
}

fn decode_account_key(text: &str) -> Result<AccountKey, StorageError> {
    if text.len() > MAX_PART_LEN * 2 + 1 {
        return Err(StorageError::new(StorageErrorKind::CorruptData));
    }
    let mut arena = Arena::try_new(ArenaConfig::default())
        .map_err(|error| StorageError::with_source(StorageErrorKind::Other, error))?;
    let jid = Jid::parse_in(text, &mut arena).map_err(|error| {
        let kind = match error {
            JidError::AllocationFailed(_) | JidError::AccessFailed(_) => StorageErrorKind::Other,
            _ => StorageErrorKind::CorruptData,
        };
        StorageError::with_source(kind, error)
    })?;
    let jid = jid
        .resolve(&arena)
        .map_err(|error| StorageError::with_source(StorageErrorKind::Other, error))?;
    // Normalizing stored keys would break cursor ordering and hide corruption.
    if jid.as_str() != text {
        return Err(StorageError::new(StorageErrorKind::CorruptData));
    }
    AccountKey::try_from(jid)
        .map_err(|error| StorageError::with_source(StorageErrorKind::CorruptData, error))
}

fn create(transaction: &WriteTransaction, account: NewAccount) -> Result<(), AccountError> {
    let mut table = transaction.open_table(ACCOUNTS).map_err(storage_error)?;
    if table
        .get(account.key.as_str())
        .map_err(storage_error)?
        .is_some()
    {
        return Err(AccountError::AlreadyExists);
    }
    validate_iterations(&account.credentials)?;
    let record = encode_credentials(&account.credentials);
    table
        .insert(account.key.as_str(), record.as_slice())
        .map_err(storage_error)?;
    Ok(())
}

fn delete(transaction: &WriteTransaction, key: &AccountKey) -> Result<(), AccountError> {
    let mut table = transaction.open_table(ACCOUNTS).map_err(storage_error)?;
    {
        let record = table
            .get(key.as_str())
            .map_err(storage_error)?
            .ok_or(AccountError::NotFound)?;
        decode_credentials(record.value())?;
    }
    table.remove(key.as_str()).map_err(storage_error)?;
    Ok(())
}

fn replace_credentials(
    transaction: &WriteTransaction,
    key: &AccountKey,
    credentials: ScramCredentials,
) -> Result<(), AccountError> {
    let mut table = transaction.open_table(ACCOUNTS).map_err(storage_error)?;
    {
        let Some(existing) = table.get(key.as_str()).map_err(storage_error)? else {
            return Err(AccountError::NotFound);
        };
        decode_credentials(existing.value())?;
    }
    validate_iterations(&credentials)?;
    let record = encode_credentials(&credentials);
    table
        .insert(key.as_str(), record.as_slice())
        .map_err(storage_error)?;
    Ok(())
}

fn validate_iterations(credentials: &ScramCredentials) -> Result<(), AccountError> {
    if credentials
        .sha1()
        .is_some_and(|verifier| verifier.iterations() != SCRAM_POLICY_ITERATIONS)
        || credentials
            .sha256()
            .is_some_and(|verifier| verifier.iterations() != SCRAM_POLICY_ITERATIONS)
    {
        return Err(AccountError::UnsupportedIterations);
    }
    Ok(())
}

struct EncodedCredentials {
    bytes: [u8; MAX_RECORD_BYTES],
    len: usize,
}

impl EncodedCredentials {
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn append(&mut self, bytes: &[u8]) {
        self.bytes[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
    }

    fn append_verifier<const N: usize>(&mut self, verifier: &ScramVerifierData<N>) {
        self.append(verifier.salt());
        self.append(&verifier.iterations().get().to_le_bytes());
        self.append(verifier.stored_key());
        self.append(verifier.server_key());
    }
}

struct DecodedCredentials {
    sha1: Option<ScramSha1Verifier>,
    sha256: Option<ScramSha256Verifier>,
}

// The disk format uses a version and hash mask, then SHA-1 before SHA-256.
// Each verifier stores salt, little-endian iterations, stored key, and server key.
fn encode_credentials(credentials: &ScramCredentials) -> EncodedCredentials {
    let mut record = EncodedCredentials {
        bytes: [0; MAX_RECORD_BYTES],
        len: 2,
    };
    record.bytes[0] = RECORD_VERSION;
    if let Some(verifier) = credentials.sha1() {
        record.bytes[1] |= SHA1;
        record.append_verifier(verifier);
    }
    if let Some(verifier) = credentials.sha256() {
        record.bytes[1] |= SHA256;
        record.append_verifier(verifier);
    }
    record
}

fn decode_credentials(mut bytes: &[u8]) -> Result<DecodedCredentials, StorageError> {
    let [version, hashes] = take(&mut bytes)?;
    if version != RECORD_VERSION {
        return Err(StorageError::new(StorageErrorKind::UnsupportedVersion));
    }
    if hashes == 0 || hashes & !(SHA1 | SHA256) != 0 {
        return Err(StorageError::new(StorageErrorKind::CorruptData));
    }
    let sha1 = if hashes & SHA1 != 0 {
        Some(decode_verifier(&mut bytes)?)
    } else {
        None
    };
    let sha256 = if hashes & SHA256 != 0 {
        Some(decode_verifier(&mut bytes)?)
    } else {
        None
    };
    if !bytes.is_empty() {
        return Err(StorageError::new(StorageErrorKind::CorruptData));
    }
    Ok(DecodedCredentials { sha1, sha256 })
}

fn decode_verifier<const N: usize>(
    bytes: &mut &[u8],
) -> Result<ScramVerifierData<N>, StorageError> {
    let salt = take(bytes)?;
    let iterations = NonZeroU32::new(u32::from_le_bytes(take(bytes)?))
        .ok_or_else(|| StorageError::new(StorageErrorKind::CorruptData))?;
    let stored_key = take(bytes)?;
    let server_key = take(bytes)?;
    Ok(ScramVerifierData::new(
        salt, iterations, stored_key, server_key,
    ))
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], StorageError> {
    let (value, remaining) = bytes
        .split_first_chunk::<N>()
        .ok_or_else(|| StorageError::new(StorageErrorKind::CorruptData))?;
    *bytes = remaining;
    Ok(*value)
}

#[cfg(test)]
mod tests;
