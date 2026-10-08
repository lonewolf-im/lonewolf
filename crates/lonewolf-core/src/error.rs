// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::{fmt, io};

use lonewolf_extension::RegistrationError;
use lonewolf_storage::StorageError;
use lonewolf_util::pool::PoolError;

use crate::config::ConfigError;
use crate::hosts::HostsError;
use crate::router::RouterFailure;

#[derive(Debug)]
pub enum RunError {
    Logging(Box<dyn Error + Send + Sync>),
    Config(ConfigError),
    Hosts(HostsError),
    Extensions {
        host: String,
        source: RegistrationError,
    },
    ExtensionCatalog(RegistrationError),
    StanzaPool(PoolError),
    Runtime(io::Error),
    WorkerCount(io::Error),
    Dispatcher(io::Error),
    DispatcherShutdown(io::Error),
    RouterShutdown(io::Error),
    RouterFailed(RouterFailure),
    Signal(io::Error),
    Admin(io::Error),
    C2s(io::Error),
    UnknownStore(String),
    StorageDirectory {
        store: String,
        source: io::Error,
    },
    Storage {
        store: String,
        source: StorageError,
    },
}

impl fmt::Display for RunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Logging(source) => write!(formatter, "cannot initialize logging: {source}"),
            Self::Config(source) => source.fmt(formatter),
            Self::Hosts(source) => write!(formatter, "cannot initialize hosts: {source}"),
            Self::Extensions { host, source } => write!(
                formatter,
                "cannot initialize extensions for {host:?}: {source}"
            ),
            Self::ExtensionCatalog(source) => {
                write!(formatter, "cannot initialize extension catalog: {source}")
            }
            Self::StanzaPool(source) => {
                write!(formatter, "cannot initialize stanza arena pool: {source}")
            }
            Self::Runtime(source) => write!(formatter, "cannot create root runtime: {source}"),
            Self::WorkerCount(source) => {
                write!(formatter, "cannot configure core workers: {source}")
            }
            Self::Dispatcher(source) => write!(formatter, "cannot start core dispatcher: {source}"),
            Self::DispatcherShutdown(source) => {
                write!(formatter, "cannot stop core dispatcher: {source}")
            }
            Self::RouterFailed(failure) => failure.fmt(formatter),
            Self::RouterShutdown(source) => write!(formatter, "cannot stop router: {source}"),
            Self::Admin(source) => write!(formatter, "admin service failed: {source}"),
            Self::C2s(source) => write!(formatter, "c2s listener service failed: {source}"),
            Self::Signal(source) => write!(formatter, "cannot wait for shutdown signal: {source}"),
            Self::UnknownStore(store) => write!(formatter, "unknown storage store {store:?}"),
            Self::StorageDirectory { store, source } => write!(
                formatter,
                "cannot create parent directory for store {store:?}: {source}"
            ),
            Self::Storage { store, source } => {
                write!(formatter, "cannot open store {store:?}: {source}")
            }
        }
    }
}

impl Error for RunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Logging(source) => Some(source.as_ref()),
            Self::RouterFailed(failure) => Some(failure),
            Self::Config(source) => Some(source),
            Self::Hosts(source) => Some(source),
            Self::Extensions { source, .. } => Some(source),
            Self::ExtensionCatalog(source) => Some(source),
            Self::StanzaPool(source) => Some(source),
            Self::Runtime(source)
            | Self::WorkerCount(source)
            | Self::Dispatcher(source)
            | Self::DispatcherShutdown(source)
            | Self::RouterShutdown(source)
            | Self::Signal(source)
            | Self::Admin(source)
            | Self::C2s(source) => Some(source),
            Self::StorageDirectory { source, .. } => Some(source),
            Self::Storage { source, .. } => Some(source),
            Self::UnknownStore(_) => None,
        }
    }
}
