// SPDX-License-Identifier: Apache-2.0

//! Relative configuration paths use the process working directory.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use lonewolf_util::pool::{DEFAULT_POOL_SIZE, MIN_POOL_SIZE, PoolConfig, PoolError};
use serde::Deserialize;

pub const DEFAULT_CONFIG_PATH: &str = "lonewolf.toml";
const MEBIBYTE: usize = 1024 * 1024;

/// Applies defaults during deserialization and rejects unknown fields.
///
/// [`Self::load`] also validates value constraints; direct deserialization does not.
#[derive(Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub logging: LoggingConfig,
    pub xmpp: XmppConfig,
    pub c2s: C2sConfig,
    pub storage: StorageConfig,
    pub account: AccountConfig,
    pub admin: AdminConfig,
}

impl Config {
    /// With no path, loads [`DEFAULT_CONFIG_PATH`] or uses defaults if that
    /// file is absent. An explicit path must refer to a readable file.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Read`] for file or UTF-8 errors,
    /// [`ConfigError::Parse`] for invalid TOML or rejected fields, and
    /// [`ConfigError::Invalid`] for values that violate configuration constraints.
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
        self.xmpp.validate()?;
        self.c2s.validate()?;
        self.storage.validate()?;
        if self.admin.socket_path.as_os_str().is_empty() {
            return Err("admin.socket_path must not be empty".into());
        }
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

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct C2sConfig {
    /// Replaces the default endpoint and must contain at least one listener.
    pub listeners: Vec<TcpListenerConfig>,
}

impl Default for C2sConfig {
    fn default() -> Self {
        Self {
            listeners: vec![TcpListenerConfig::default()],
        }
    }
}

impl C2sConfig {
    fn validate(&self) -> Result<(), String> {
        if self.listeners.is_empty() {
            return Err("c2s.listeners must define at least one listener".into());
        }
        for (index, listener) in self.listeners.iter().enumerate() {
            let address = listener.address;
            if address.port() == 0 {
                continue;
            }
            for (previous, other) in self.listeners[..index].iter().enumerate() {
                let other = other.address;
                if address.port() == other.port()
                    && address.is_ipv4() == other.is_ipv4()
                    && (address == other
                        || address.ip().is_unspecified()
                        || other.ip().is_unspecified())
                {
                    return Err(format!(
                        "c2s.listeners[{index}] overlaps c2s.listeners[{previous}]"
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct TcpListenerConfig {
    /// IPv6 addresses accept IPv6 only; port zero selects one port for all workers.
    pub address: SocketAddr,
}

impl Default for TcpListenerConfig {
    fn default() -> Self {
        Self {
            address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 5222)),
        }
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct XmppConfig {
    pub stanza_pool_size_mib: usize,
}

impl Default for XmppConfig {
    fn default() -> Self {
        Self {
            stanza_pool_size_mib: DEFAULT_POOL_SIZE / MEBIBYTE,
        }
    }
}

impl XmppConfig {
    fn validate(&self) -> Result<(), String> {
        if self.stanza_pool_size_mib < MIN_POOL_SIZE / MEBIBYTE
            || !self.stanza_pool_size_mib.is_power_of_two()
        {
            return Err(format!(
                "xmpp.stanza_pool_size_mib must be a power of two of at least {} MiB",
                MIN_POOL_SIZE / MEBIBYTE
            ));
        }
        if self.stanza_pool_size_mib.checked_mul(MEBIBYTE).is_none() {
            return Err("xmpp.stanza_pool_size_mib is too large for this platform".into());
        }
        Ok(())
    }

    pub(crate) fn stanza_pool_config(
        &self,
        worker_count: NonZeroUsize,
    ) -> Result<PoolConfig, PoolError> {
        let total_bytes = self
            .stanza_pool_size_mib
            .checked_mul(MEBIBYTE)
            .and_then(NonZeroUsize::new)
            .ok_or(PoolError::InvalidConfiguration)?;
        Ok(PoolConfig {
            total_bytes,
            shards_per_bucket: worker_count,
        })
    }
}

#[derive(Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AccountConfig {
    /// Selects a named store, or the default in [`StorageConfig`] when absent.
    pub storage: Option<String>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    pub enabled: bool,
    pub socket_path: PathBuf,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            socket_path: PathBuf::from("./run/lonewolf/admin.sock"),
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
    /// Selects a configured store; a sole store is selected automatically.
    pub default: String,
    /// Replaces the built-in store map when present in TOML.
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

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::num::NonZeroUsize;

    use super::XmppConfig;

    #[test]
    fn stanza_pool_shard_count_matches_worker_count() -> Result<(), Box<dyn Error>> {
        let worker_count = NonZeroUsize::new(3).ok_or("worker count must be nonzero")?;

        let config = XmppConfig::default().stanza_pool_config(worker_count)?;

        assert_eq!(config.shards_per_bucket, worker_count);
        Ok(())
    }
}
