// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::{fmt, io};

use lonewolf_storage::StorageError;
use lonewolf_util::pool::PoolError;

use crate::config::ConfigError;
use crate::hosts::HostsError;

#[derive(Debug)]
pub enum RunError {
    Logging(Box<dyn Error + Send + Sync>),
    Config(ConfigError),
    Hosts(HostsError),
    StanzaPool(PoolError),
    Runtime(io::Error),
    WorkerCount(io::Error),
    Dispatcher(io::Error),
    DispatcherShutdown(io::Error),
    Router(io::Error),
    RouterShutdown(io::Error),
    Signal(io::Error),
    Admin(io::Error),
    C2s(io::Error),
    UnknownStore(String),
    StorageDirectory { store: String, source: io::Error },
    Storage { store: String, source: StorageError },
    Accounts { store: String, source: StorageError },
}

impl fmt::Display for RunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Logging(source) => write!(formatter, "cannot initialize logging: {source}"),
            Self::Config(source) => source.fmt(formatter),
            Self::Hosts(source) => write!(formatter, "cannot initialize hosts: {source}"),
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
            Self::Router(source) => write!(formatter, "cannot start router: {source}"),
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
            Self::Accounts { store, source } => write!(
                formatter,
                "cannot initialize account repository in store {store:?}: {source}"
            ),
        }
    }
}

impl Error for RunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Logging(source) => Some(source.as_ref()),
            Self::Config(source) => Some(source),
            Self::Hosts(source) => Some(source),
            Self::StanzaPool(source) => Some(source),
            Self::Runtime(source)
            | Self::WorkerCount(source)
            | Self::Dispatcher(source)
            | Self::DispatcherShutdown(source)
            | Self::Router(source)
            | Self::RouterShutdown(source)
            | Self::Signal(source)
            | Self::Admin(source)
            | Self::C2s(source) => Some(source),
            Self::StorageDirectory { source, .. } => Some(source),
            Self::Storage { source, .. } | Self::Accounts { source, .. } => Some(source),
            Self::UnknownStore(_) => None,
        }
    }
}
