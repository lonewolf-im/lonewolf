// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageErrorKind {
    Unavailable,
    CorruptData,
    UnsupportedVersion,
    /// The write may have committed; an error does not imply rollback.
    CommitUnknown,
    Other,
}

/// Omits backend details from [`Debug`](fmt::Debug) and [`Display`](fmt::Display).
///
/// The source chain can contain credentials or account identifiers and must
/// not be logged without redaction.
pub struct StorageError {
    kind: StorageErrorKind,
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl StorageError {
    pub fn new(kind: StorageErrorKind) -> Self {
        Self { kind, source: None }
    }

    pub fn with_source(kind: StorageErrorKind, source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            kind,
            source: Some(Box::new(source)),
        }
    }

    pub fn kind(&self) -> StorageErrorKind {
        self.kind
    }
}

impl fmt::Debug for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StorageError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            StorageErrorKind::Unavailable => "storage unavailable",
            StorageErrorKind::CorruptData => "stored data is invalid",
            StorageErrorKind::UnsupportedVersion => "stored data version is not supported",
            StorageErrorKind::CommitUnknown => "storage commit outcome is unknown",
            StorageErrorKind::Other => "storage operation failed",
        })
    }
}

impl Error for StorageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_deref().map(|source| source as &dyn Error)
    }
}
