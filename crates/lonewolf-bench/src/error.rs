// SPDX-License-Identifier: Apache-2.0

use std::{error::Error, fmt};

pub type BenchResult<T> = Result<T, BenchError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidConfig,
    ConfigRead,
    InvalidPath,
    OutputExists,
    NotImplemented,
    Runtime,
    UnsupportedPlatform,
    IncompatibleComparison,
    ArtifactFailure,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidConfig => "invalid_config",
            Self::ConfigRead => "config_read",
            Self::InvalidPath => "invalid_path",
            Self::OutputExists => "output_exists",
            Self::NotImplemented => "not_implemented",
            Self::Runtime => "runtime",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::IncompatibleComparison => "incompatible_comparison",
            Self::ArtifactFailure => "artifact_failure",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct BenchError {
    pub code: ErrorCode,
    context: &'static str,
}

impl BenchError {
    pub const fn new(code: ErrorCode, context: &'static str) -> Self {
        Self { code, context }
    }
    pub const fn context(&self) -> &'static str {
        self.context
    }
    pub const fn exit_code(&self) -> u8 {
        2
    }
    pub const fn staged() -> Self {
        Self::new(ErrorCode::NotImplemented, "command is not implemented")
    }
}
impl fmt::Display for BenchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.context)
    }
}
impl fmt::Debug for BenchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl Error for BenchError {}
