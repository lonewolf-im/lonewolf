// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroU32;
use std::path::Path;
use std::sync::Arc;

use ::redb::{Database, ReadableDatabase, ReadableTable, TableDefinition, TableHandle};
use lonewolf_auth::scram::{
    ScramCredentials, ScramHash, ScramSha1Verifier, ScramSha256Verifier, ScramVerifier,
    ScramVerifierData,
};

use crate::account::{Account, AccountError, AccountKey, AccountRepository, NewAccount};
use crate::redb::{METADATA, begin_write, commit_error, open_database, storage_error};
use crate::{StorageError, StorageErrorKind};

const ACCOUNTS: TableDefinition<&str, &[u8]> = TableDefinition::new("lonewolf_accounts");
const SCHEMA_KEY: &str = "accounts_schema";
const SCHEMA_VERSION: u32 = 1;
const RECORD_VERSION: u8 = 1;
const SHA1: u8 = 1;
const SHA256: u8 = 2;
const MAX_RECORD_BYTES: usize = 2 + (16 + 4 + 20 * 2) + (16 + 4 + 32 * 2);

pub struct RedbAccountRepository {
    database: Arc<Database>,
}

impl RedbAccountRepository {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        Self::from_database(Arc::new(open_database(path)?))
    }

    pub fn from_database(database: Arc<Database>) -> Result<Self, StorageError> {
        let transaction = begin_write(&database)?;
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
        let record = encode_credentials(&account.credentials);
        let transaction = begin_write(&self.database)?;
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

    async fn get(&self, key: &AccountKey) -> Result<Option<Account>, AccountError> {
        let transaction = self.database.begin_read().map_err(storage_error)?;
        let table = transaction.open_table(ACCOUNTS).map_err(storage_error)?;
        let Some(record) = table.get(key.as_str()).map_err(storage_error)? else {
            return Ok(None);
        };
        decode_credentials(record.value())?;
        Ok(Some(Account { key: key.clone() }))
    }

    async fn get_scram(
        &self,
        key: &AccountKey,
        hash: ScramHash,
    ) -> Result<Option<ScramVerifier>, AccountError> {
        let transaction = self.database.begin_read().map_err(storage_error)?;
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

    async fn replace_credentials(
        &self,
        key: &AccountKey,
        credentials: ScramCredentials,
    ) -> Result<(), AccountError> {
        let record = encode_credentials(&credentials);
        let transaction = begin_write(&self.database)?;
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
