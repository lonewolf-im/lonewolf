// SPDX-License-Identifier: Apache-2.0

use lonewolf_util::capacity::Capacity;
use std::collections::{BTreeMap, btree_map::Entry};
use std::fs::DirBuilder;
use std::os::unix::fs::DirBuilderExt;
use std::sync::Arc;

use lonewolf_storage::RedbStorage;

use crate::RunError;
use crate::config::{StorageConfig, StoreConfig};

/// Opens each selected store once so every consumer shares its lock and limits.
pub(crate) struct StoreRegistry<'config> {
    config: &'config StorageConfig,
    stores: BTreeMap<&'config str, RedbStorage>,
    capacity: Option<Arc<Capacity>>,
}

impl<'config> StoreRegistry<'config> {
    #[cfg(test)]
    pub(crate) fn new(config: &'config StorageConfig) -> Self {
        Self {
            config,
            stores: BTreeMap::new(),
            capacity: None,
        }
    }

    pub(crate) fn with_capacity(config: &'config StorageConfig, capacity: Arc<Capacity>) -> Self {
        Self {
            config,
            stores: BTreeMap::new(),
            capacity: Some(capacity),
        }
    }

    pub(crate) fn storage(&mut self, name: &str) -> Result<RedbStorage, RunError> {
        self.store(name).cloned()
    }

    fn store(&mut self, name: &str) -> Result<&RedbStorage, RunError> {
        let (name, config) = self
            .config
            .stores
            .get_key_value(name)
            .ok_or_else(|| RunError::UnknownStore(name.into()))?;
        match self.stores.entry(name.as_str()) {
            Entry::Occupied(entry) => Ok(entry.into_mut()),
            Entry::Vacant(entry) => {
                let storage = match config {
                    StoreConfig::Redb { path } => {
                        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                            let mut builder = DirBuilder::new();
                            builder.recursive(true);
                            builder.mode(0o700);
                            builder.create(parent).map_err(|source| {
                                RunError::StorageDirectory {
                                    store: name.clone(),
                                    source,
                                }
                            })?;
                        }
                        match &self.capacity {
                            Some(capacity) => {
                                RedbStorage::open_with_capacity(path, Arc::clone(capacity))
                            }
                            None => RedbStorage::open(path),
                        }
                        .map_err(|source| RunError::Storage {
                            store: name.clone(),
                            source,
                        })?
                    }
                };
                Ok(entry.insert(storage))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::error::Error;
    use std::fs;

    use lonewolf_storage::RedbStorage;

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
        let first = stores.storage("accounts")?;
        let second = stores.storage("accounts")?;

        assert!(path.is_file());
        assert!(!unused_path.exists());
        assert!(!directory.path().join("unused").exists());
        assert!(RedbStorage::open(&path).is_err());
        drop(stores);
        drop(first);
        assert!(RedbStorage::open(&path).is_err());
        drop(second);
        let _reopened = RedbStorage::open(&path)?;
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
            stores.storage("accounts"),
            Err(RunError::Storage { store, .. }) if store == "accounts"
        ));
        assert_eq!(fs::read(path)?, contents);
        Ok(())
    }
}
