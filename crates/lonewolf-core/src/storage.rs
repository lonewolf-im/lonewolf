// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, btree_map::Entry};
use std::fs::DirBuilder;
#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;

use lonewolf_storage::RedbDatabase;
use lonewolf_storage::account::redb::RedbAccountRepository;

use crate::RunError;
use crate::config::{StorageConfig, StoreConfig};

pub(crate) struct StoreRegistry<'config> {
    config: &'config StorageConfig,
    databases: BTreeMap<&'config str, RedbDatabase>,
}

impl<'config> StoreRegistry<'config> {
    pub(crate) fn new(config: &'config StorageConfig) -> Self {
        Self {
            config,
            databases: BTreeMap::new(),
        }
    }

    pub(crate) fn accounts(&mut self, name: &str) -> Result<RedbAccountRepository, RunError> {
        let database = self.database(name)?;
        RedbAccountRepository::from_database(database.clone()).map_err(|source| {
            RunError::Accounts {
                store: name.into(),
                source,
            }
        })
    }

    fn database(&mut self, name: &str) -> Result<&RedbDatabase, RunError> {
        let (name, config) = self
            .config
            .stores
            .get_key_value(name)
            .ok_or_else(|| RunError::UnknownStore(name.into()))?;
        match self.databases.entry(name.as_str()) {
            Entry::Occupied(entry) => Ok(entry.into_mut()),
            Entry::Vacant(entry) => {
                let database = match config {
                    StoreConfig::Redb { path } => {
                        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                            let mut builder = DirBuilder::new();
                            builder.recursive(true);
                            #[cfg(unix)]
                            builder.mode(0o700);
                            builder.create(parent).map_err(|source| {
                                RunError::StorageDirectory {
                                    store: name.clone(),
                                    source,
                                }
                            })?;
                        }
                        RedbDatabase::open(path).map_err(|source| RunError::Storage {
                            store: name.clone(),
                            source,
                        })?
                    }
                };
                Ok(entry.insert(database))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::error::Error;
    use std::fs;

    use lonewolf_storage::RedbDatabase;

    use super::StoreRegistry;
    use crate::RunError;
    use crate::config::{StorageConfig, StoreConfig};

    type TestResult = Result<(), Box<dyn Error>>;

    #[test]
    fn repositories_share_the_selected_database_until_the_last_owner_drops() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("data/accounts.redb");
        let unused_path = directory.path().join("unused/archive.redb");
        let config = StorageConfig {
            default: "archive".into(),
            stores: BTreeMap::from([
                ("accounts".into(), StoreConfig::Redb { path: path.clone() }),
                (
                    "archive".into(),
                    StoreConfig::Redb {
                        path: unused_path.clone(),
                    },
                ),
            ]),
        };
        let mut stores = StoreRegistry::new(&config);
        let first = stores.accounts("accounts")?;
        let second = stores.accounts("accounts")?;

        assert!(path.is_file());
        assert!(!unused_path.exists());
        assert!(!directory.path().join("unused").exists());
        assert!(RedbDatabase::open(&path).is_err());
        drop(stores);
        drop(first);
        assert!(RedbDatabase::open(&path).is_err());
        drop(second);
        let _reopened = RedbDatabase::open(&path)?;
        Ok(())
    }

    #[test]
    fn invalid_database_is_preserved_and_reports_the_store() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("invalid.redb");
        let contents = b"not a redb database";
        fs::write(&path, contents)?;
        let config = StorageConfig {
            default: "accounts".into(),
            stores: BTreeMap::from([("accounts".into(), StoreConfig::Redb { path: path.clone() })]),
        };
        let mut stores = StoreRegistry::new(&config);

        assert!(matches!(
            stores.accounts("accounts"),
            Err(RunError::Storage { store, .. }) if store == "accounts"
        ));
        assert_eq!(fs::read(path)?, contents);
        Ok(())
    }
}
