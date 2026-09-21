// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub const DEFAULT_CONFIG_PATH: &str = "lonewolf.yaml";

#[derive(Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub admin: AdminConfig,
}

impl Config {
    /// With no path, loads `lonewolf.yaml` or uses defaults if that file is absent.
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

        serde_saphyr::from_str::<Option<Self>>(&contents)
            .map(Option::unwrap_or_default)
            .map_err(|source| ConfigError::Parse {
                path: selected_path.to_path_buf(),
                source: Box::new(source),
            })
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

#[derive(Debug)]
pub enum ConfigError {
    Read {
        path: PathBuf,
        source: io::Error,
    },
    Parse {
        path: PathBuf,
        source: Box<serde_saphyr::Error>,
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
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source.as_ref()),
        }
    }
}
