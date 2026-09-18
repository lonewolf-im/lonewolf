// SPDX-License-Identifier: Apache-2.0

use ::redb::{CommitError, Error};

use crate::{StorageError, StorageErrorKind};

pub(crate) fn storage_error(error: impl Into<Error>) -> StorageError {
    let error = error.into();
    let kind = match &error {
        Error::Corrupted(_)
        | Error::TableTypeMismatch { .. }
        | Error::TableIsMultimap(_)
        | Error::TableIsNotMultimap(_)
        | Error::TypeDefinitionChanged { .. }
        | Error::TableDoesNotExist(_) => StorageErrorKind::CorruptData,
        Error::UpgradeRequired(_) => StorageErrorKind::UnsupportedVersion,
        Error::Io(_)
        | Error::DatabaseAlreadyOpen
        | Error::DatabaseClosed
        | Error::PreviousIo
        | Error::LockPoisoned(_) => StorageErrorKind::Unavailable,
        _ => StorageErrorKind::Other,
    };
    StorageError::with_source(kind, error)
}

pub(crate) fn commit_error(error: CommitError) -> StorageError {
    if matches!(error, CommitError::TransactionPoisoned) {
        storage_error(error)
    } else {
        StorageError::with_source(StorageErrorKind::CommitUnknown, error)
    }
}
