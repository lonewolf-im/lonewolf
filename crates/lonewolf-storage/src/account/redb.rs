// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroU32;
use std::ops::Bound;
use std::path::Path;

use ::redb::{Database, OwnedRange, ReadableDatabase, ReadableTable, TableDefinition, TableHandle};
use futures_util::{Stream, stream};
use lonewolf_auth::scram::{
    ScramCredentials, ScramHash, ScramSha1Verifier, ScramSha256Verifier, ScramVerifier,
    ScramVerifierData,
};
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_xmpp::jid::{Jid, JidError, MAX_PART_LEN};

use crate::account::{Account, AccountError, AccountKey, AccountRepository, NewAccount};
use crate::redb::{METADATA, begin_write, commit_error, storage_error};
use crate::{RedbDatabase, StorageError, StorageErrorKind};

const ACCOUNTS: TableDefinition<&str, &[u8]> = TableDefinition::new("lonewolf_accounts");
const SCHEMA_KEY: &str = "accounts_schema";
const SCHEMA_VERSION: u32 = 1;
const RECORD_VERSION: u8 = 1;
const SHA1: u8 = 1;
const SHA256: u8 = 2;
const MAX_RECORD_BYTES: usize = 2 + (16 + 4 + 20 * 2) + (16 + 4 + 32 * 2);

/// Account operations use a shared, bounded blocking pool.
/// Dropping a future or stream does not stop an operation that has started.
pub struct RedbAccountRepository {
    database: RedbDatabase,
}

impl RedbAccountRepository {
    /// Opens the database and initializes its schema synchronously.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        Self::from_database(RedbDatabase::open(path)?)
    }

    /// Checks and initializes the schema synchronously.
    pub fn from_database(database: RedbDatabase) -> Result<Self, StorageError> {
        let transaction = begin_write(database.as_ref())?;
        let initialize;
        {
            let accounts_exist = transaction
                .list_tables()
                .map_err(storage_error)?
                .any(|table| table.name() == ACCOUNTS.name());
            let mut metadata = transaction.open_table(METADATA).map_err(storage_error)?;
            let version = metadata
                .get(SCHEMA_KEY)
                .map_err(storage_error)?
                .map(|value| value.value());
            initialize = match version {
                Some(SCHEMA_VERSION) if accounts_exist => false,
                None if !accounts_exist => true,
                Some(SCHEMA_VERSION) | None => {
                    return Err(StorageError::new(StorageErrorKind::CorruptData));
                }
                Some(_) => {
                    return Err(StorageError::new(StorageErrorKind::UnsupportedVersion));
                }
            };
            transaction.open_table(ACCOUNTS).map_err(storage_error)?;
            if initialize {
                metadata
                    .insert(SCHEMA_KEY, SCHEMA_VERSION)
                    .map_err(storage_error)?;
            }
        }
        if initialize {
            transaction.commit().map_err(commit_error)?;
        } else {
            transaction.abort().map_err(storage_error)?;
        }
        Ok(Self { database })
    }
}

impl AccountRepository for RedbAccountRepository {
    async fn create(&self, account: NewAccount) -> Result<(), AccountError> {
        self.database
            .write(move |database| create(database, account))
            .await
    }

    async fn get(&self, key: &AccountKey) -> Result<Option<Account>, AccountError> {
        let key = key.clone();
        self.database.read(move |database| get(database, key)).await
    }

    fn list(&self, after: Option<AccountKey>) -> impl Stream<Item = Result<Account, AccountError>> {
        list(&self.database, after)
    }

    async fn delete(&self, key: &AccountKey) -> Result<(), AccountError> {
        let key = key.clone();
        self.database
            .write(move |database| delete(database, &key))
            .await
    }

    async fn get_scram(
        &self,
        key: &AccountKey,
        hash: ScramHash,
    ) -> Result<Option<ScramVerifier>, AccountError> {
        let key = key.clone();
        self.database
            .read(move |database| get_scram(database, &key, hash))
            .await
    }

    async fn replace_credentials(
        &self,
        key: &AccountKey,
        credentials: ScramCredentials,
    ) -> Result<(), AccountError> {
        let key = key.clone();
        self.database
            .write(move |database| replace_credentials(database, &key, credentials))
            .await
    }
}

fn create(database: &Database, account: NewAccount) -> Result<(), AccountError> {
    let record = encode_credentials(&account.credentials);
    let transaction = begin_write(database)?;
    {
        let mut table = transaction.open_table(ACCOUNTS).map_err(storage_error)?;
        if table
            .get(account.key.as_str())
            .map_err(storage_error)?
            .is_some()
        {
            return Err(AccountError::AlreadyExists);
        }
        table
            .insert(account.key.as_str(), record.as_slice())
            .map_err(storage_error)?;
    }
    transaction.commit().map_err(commit_error)?;
    Ok(())
}

fn get(database: &Database, key: AccountKey) -> Result<Option<Account>, AccountError> {
    let transaction = database.begin_read().map_err(storage_error)?;
    let table = transaction.open_table(ACCOUNTS).map_err(storage_error)?;
    let Some(record) = table.get(key.as_str()).map_err(storage_error)? else {
        return Ok(None);
    };
    decode_credentials(record.value())?;
    Ok(Some(Account { key }))
}

struct ListState {
    after: Option<AccountKey>,
    entries: Option<OwnedRange<&'static str, &'static [u8]>>,
}

fn list(
    database: &RedbDatabase,
    after: Option<AccountKey>,
) -> impl Stream<Item = Result<Account, AccountError>> {
    let state = ListState {
        after,
        entries: None,
    };
    stream::try_unfold(state, move |state| async move {
        database
            .read(move |database| {
                let mut entries = match state.entries {
                    Some(entries) => entries,
                    None => open_range(database, state.after)?,
                };
                let Some(entry) = entries.next() else {
                    return Ok(None);
                };
                let (key, record) = entry.map_err(storage_error)?;
                decode_credentials(record.value())?;
                let account = Account {
                    key: decode_account_key(key.value())?,
                };
                Ok(Some((
                    account,
                    ListState {
                        after: None,
                        entries: Some(entries),
                    },
                )))
            })
            .await
    })
}

fn open_range(
    database: &Database,
    after: Option<AccountKey>,
) -> Result<OwnedRange<&'static str, &'static [u8]>, AccountError> {
    let transaction = database.begin_read().map_err(storage_error)?;
    let table = transaction.open_table(ACCOUNTS).map_err(storage_error)?;
    let start = after
        .as_ref()
        .map_or(Bound::Unbounded, |key| Bound::Excluded(key.as_str()));
    table
        .range_owned::<&str>((start, Bound::Unbounded))
        .map_err(|error| storage_error(error).into())
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
    if jid.as_str() != text {
        return Err(StorageError::new(StorageErrorKind::CorruptData));
    }
    AccountKey::try_from(jid)
        .map_err(|error| StorageError::with_source(StorageErrorKind::CorruptData, error))
}

fn delete(database: &Database, key: &AccountKey) -> Result<(), AccountError> {
    let transaction = begin_write(database)?;
    {
        let mut table = transaction.open_table(ACCOUNTS).map_err(storage_error)?;
        let record = table
            .remove(key.as_str())
            .map_err(storage_error)?
            .ok_or(AccountError::NotFound)?;
        decode_credentials(record.value())?;
    }
    transaction.commit().map_err(commit_error)?;
    Ok(())
}

fn get_scram(
    database: &Database,
    key: &AccountKey,
    hash: ScramHash,
) -> Result<Option<ScramVerifier>, AccountError> {
    let transaction = database.begin_read().map_err(storage_error)?;
    let table = transaction.open_table(ACCOUNTS).map_err(storage_error)?;
    let Some(record) = table.get(key.as_str()).map_err(storage_error)? else {
        return Ok(None);
    };
    let credentials = decode_credentials(record.value())?;
    Ok(match hash {
        ScramHash::Sha1 => credentials.sha1.map(ScramVerifier::Sha1),
        ScramHash::Sha256 => credentials.sha256.map(ScramVerifier::Sha256),
    })
}

fn replace_credentials(
    database: &Database,
    key: &AccountKey,
    credentials: ScramCredentials,
) -> Result<(), AccountError> {
    let record = encode_credentials(&credentials);
    let transaction = begin_write(database)?;
    {
        let mut table = transaction.open_table(ACCOUNTS).map_err(storage_error)?;
        {
            let Some(existing) = table.get(key.as_str()).map_err(storage_error)? else {
                return Err(AccountError::NotFound);
            };
            decode_credentials(existing.value())?;
        }
        table
            .insert(key.as_str(), record.as_slice())
            .map_err(storage_error)?;
    }
    transaction.commit().map_err(commit_error)?;
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
