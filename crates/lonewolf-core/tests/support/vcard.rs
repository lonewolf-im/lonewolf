// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;

use compio::runtime::Runtime;
use lonewolf_auth::scram::{
    SCRAM_POLICY_ITERATIONS, ScramCredentials, ScramHash, ScramIterations, ScramVerifier,
};
use lonewolf_storage::account::{AccountKey, AccountWrites, NewAccount};
use lonewolf_storage::vcard::VCardReads;
use lonewolf_storage::{RedbStorage, Storage, WriteTransaction};
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_xmpp::jid::Jid;

use super::{PASSWORD, TestResult};

pub fn key(jid: &str) -> TestResult<AccountKey> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    Ok(AccountKey::try_from(
        Jid::parse_in(jid, &mut arena)?.resolve(&arena)?,
    )?)
}

pub fn seed(directory: &Path, records: &[(&str, &[u8])]) -> TestResult {
    fs::create_dir_all(directory.join("data"))?;
    let path = directory.join("data/lonewolf.dat");
    let storage = RedbStorage::open(&path)?;
    Runtime::new()?.block_on(async {
        let mut transaction = storage.begin_write().await?;
        for (jid, _) in records {
            transaction
                .create_account(NewAccount {
                    key: key(jid)?,
                    credentials: ScramCredentials::new(ScramVerifier::derive(
                        ScramHash::Sha256,
                        PASSWORD,
                        [4; 16],
                        ScramIterations::new(SCRAM_POLICY_ITERATIONS.get())?,
                    )?),
                })
                .await?;
        }
        transaction.commit().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    drop(storage);
    let database = redb::Database::open(path)?;
    let transaction = database.begin_write()?;
    {
        let mut table =
            transaction.open_table(redb::TableDefinition::<&str, &[u8]>::new("lonewolf_vcards"))?;
        for (jid, bytes) in records {
            table.insert(*jid, *bytes)?;
        }
    }
    transaction.commit()?;
    Ok(())
}

pub fn assert_absent(directory: &Path, jid: &str) -> TestResult {
    let storage = RedbStorage::open(directory.join("data/lonewolf.dat"))?;
    Runtime::new()?.block_on(async {
        assert!(
            storage
                .begin_read()
                .await?
                .vcard(&key(jid)?)
                .await?
                .is_none()
        );
        Ok(())
    })
}

pub fn assert_raw(directory: &Path, jid: &str, expected: &[u8]) -> TestResult {
    use redb::ReadableDatabase;
    let database = redb::Database::open(directory.join("data/lonewolf.dat"))?;
    let transaction = database.begin_read()?;
    let table =
        transaction.open_table(redb::TableDefinition::<&str, &[u8]>::new("lonewolf_vcards"))?;
    assert_eq!(
        table.get(jid)?.ok_or("missing retained row")?.value(),
        expected
    );
    Ok(())
}
