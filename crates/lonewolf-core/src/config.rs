// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub const DEFAULT_CONFIG_PATH: &str = "lonewolf.toml";

#[derive(Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub logging: LoggingConfig,
    pub storage: StorageConfig,
    pub account: AccountConfig,
    pub admin: AdminConfig,
}

impl Config {
    /// With no path, loads `lonewolf.toml` or uses defaults if that file is absent.
    /// An explicit path must refer to a readable configuration file.
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        let selected_path = path.unwrap_or_else(|| Path::new(DEFAULT_CONFIG_PATH));
        let contents = match fs::read_to_string(selected_path) {
            Ok(contents) => contents,
            Err(source) if path.is_none() && source.kind() == io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(source) => {
                return Err(ConfigError::Read {
                    path: selected_path.to_path_buf(),
                    source,
                });
            }
        };

        let config: Self = toml::from_str(&contents).map_err(|source| ConfigError::Parse {
            path: selected_path.to_path_buf(),
            source,
        })?;
        config.validate().map_err(|reason| ConfigError::Invalid {
            path: selected_path.to_path_buf(),
            reason,
        })?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        self.storage.validate()?;
        if let Some(store) = &self.account.storage
            && !self.storage.stores.contains_key(store)
        {
            return Err(format!(
                "account.storage references unknown store {store:?}"
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AccountConfig {
    pub storage: Option<String>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    pub enabled: bool,
    pub listen_addr: SocketAddr,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 8080)),
        }
    }
}

#[derive(Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    pub level: LogLevel,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(try_from = "StorageConfigInput")]
pub struct StorageConfig {
    pub default: String,
    pub stores: BTreeMap<String, StoreConfig>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            default: "primary".into(),
            stores: default_stores(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StorageConfigInput {
    default: Option<String>,
    #[serde(default = "default_stores")]
    stores: BTreeMap<String, StoreConfig>,
}

impl TryFrom<StorageConfigInput> for StorageConfig {
    type Error = &'static str;

    fn try_from(input: StorageConfigInput) -> Result<Self, Self::Error> {
        let (first_name, _) = input
            .stores
            .first_key_value()
            .ok_or("storage.stores must define at least one store")?;
        let default = match input.default {
            Some(default) => default,
            None if input.stores.len() == 1 => first_name.clone(),
            None => {
                return Err("storage.default is required when multiple stores are defined");
            }
        };
        Ok(Self {
            default,
            stores: input.stores,
        })
    }
}

fn default_stores() -> BTreeMap<String, StoreConfig> {
    BTreeMap::from([(
        "primary".into(),
        StoreConfig::Redb {
            path: PathBuf::from("./data/lonewolf.dat"),
        },
    )])
}

impl StorageConfig {
    fn validate(&self) -> Result<(), String> {
        if !self.stores.contains_key(&self.default) {
            return Err(format!(
                "storage.default references unknown store {:?}",
                self.default
            ));
        }
        for (name, store) in &self.stores {
            if name.is_empty() {
                return Err("storage store names must not be empty".into());
            }
            match store {
                StoreConfig::Redb { path } if path.as_os_str().is_empty() => {
                    return Err(format!("path for store {name:?} must not be empty"));
                }
                StoreConfig::Redb { .. } => {}
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "backend", rename_all = "lowercase", deny_unknown_fields)]
pub enum StoreConfig {
    Redb { path: PathBuf },
}

#[derive(Debug)]
pub enum ConfigError {
    Read {
        path: PathBuf,
        source: io::Error,
    },
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    Invalid {
        path: PathBuf,
        reason: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(
                    formatter,
                    "cannot read configuration file '{}': {source}",
                    path.display()
                )
            }
            Self::Parse { path, source } => {
                write!(
                    formatter,
                    "invalid configuration file '{}': {source}",
                    path.display()
                )
            }
            Self::Invalid { path, reason } => write!(
                formatter,
                "invalid configuration file '{}': {reason}",
                path.display()
            ),
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
            Self::Invalid { .. } => None,
        }
    }
}
