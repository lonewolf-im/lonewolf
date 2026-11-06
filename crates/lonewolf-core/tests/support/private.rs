// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;

use compio::runtime::Runtime;
use lonewolf_auth::scram::{
    SCRAM_POLICY_ITERATIONS, ScramCredentials, ScramHash, ScramIterations, ScramVerifier,
};
use lonewolf_storage::account::{AccountKey, AccountWrites, NewAccount};
use lonewolf_storage::{RedbStorage, Storage, WriteTransaction};
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_xmpp::jid::Jid;
use redb::{ReadableDatabase, ReadableTable};

use super::{PASSWORD, TestResult};

const TABLE: redb::TableDefinition<(&str, &str, &str), &[u8]> =
    redb::TableDefinition::new("lonewolf_private_xml");

fn key(jid: &str) -> TestResult<AccountKey> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    Ok(AccountKey::try_from(
        Jid::parse_in(jid, &mut arena)?.resolve(&arena)?,
    )?)
}

pub fn seed(directory: &Path, owner: &str, rows: &[(&str, &str, &[u8])]) -> TestResult {
    fs::create_dir_all(directory.join("data"))?;
    let path = directory.join("data/lonewolf.dat");
    let storage = RedbStorage::open(&path)?;
    Runtime::new()?.block_on(async {
        let mut transaction = storage.begin_write().await?;
        transaction
            .create_account(NewAccount {
                key: key(owner)?,
                credentials: ScramCredentials::new(ScramVerifier::derive(
                    ScramHash::Sha256,
                    PASSWORD,
                    [4; 16],
                    ScramIterations::new(SCRAM_POLICY_ITERATIONS.get())?,
                )?),
            })
            .await?;
        transaction.commit().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    drop(storage);
    let database = redb::Database::open(path)?;
    let transaction = database.begin_write()?;
    {
        let mut table = transaction.open_table(TABLE)?;
        for (namespace, name, bytes) in rows {
            table.insert((owner, *namespace, *name), *bytes)?;
        }
    }
    transaction.commit()?;
    Ok(())
}

pub fn rows(directory: &Path, owner: &str) -> TestResult<Vec<(String, String, Vec<u8>)>> {
    let database = redb::Database::open(directory.join("data/lonewolf.dat"))?;
    let transaction = database.begin_read()?;
    let table = transaction.open_table(TABLE)?;
    let mut rows = Vec::new();
    for entry in table.iter()? {
        let (key, value) = entry?;
        let (row_owner, namespace, name) = key.value();
        if row_owner == owner {
            rows.push((
                namespace.to_owned(),
                name.to_owned(),
                value.value().to_vec(),
            ));
        }
    }
    Ok(rows)
}
