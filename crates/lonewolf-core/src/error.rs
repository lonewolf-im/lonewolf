// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::{fmt, io};

use crate::config::ConfigError;

#[derive(Debug)]
pub enum RunError {
    Logging(Box<dyn Error + Send + Sync>),
    Config(ConfigError),
    Runtime(io::Error),
    Signal(io::Error),
}

impl fmt::Display for RunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Logging(source) => write!(formatter, "cannot initialize logging: {source}"),
            Self::Config(source) => source.fmt(formatter),
            Self::Runtime(source) => write!(formatter, "cannot create root runtime: {source}"),
            Self::Signal(source) => write!(formatter, "cannot wait for shutdown signal: {source}"),
        }
    }
}

impl Error for RunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Logging(source) => Some(source.as_ref()),
            Self::Config(source) => Some(source),
            Self::Runtime(source) | Self::Signal(source) => Some(source),
        }
    }
}
