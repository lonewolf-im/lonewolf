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
    pub admin: AdminConfig,
    pub logging: LoggingConfig,
    pub storage: StorageConfig,
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
        config
            .storage
            .validate()
            .map_err(|reason| ConfigError::Invalid {
                path: selected_path.to_path_buf(),
                reason,
            })?;
        Ok(config)
    }
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
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    pub default: String,
    pub stores: BTreeMap<String, StoreConfig>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            default: "primary".into(),
            stores: BTreeMap::from([(
                "primary".into(),
                StoreConfig::Redb {
                    path: PathBuf::from("./data/lonewolf.redb"),
                },
            )]),
        }
    }
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
