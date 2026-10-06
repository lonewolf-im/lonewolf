// SPDX-License-Identifier: Apache-2.0

use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_xmpp::jid::{Jid, JidError, JidRef};

use crate::{StorageError, StorageErrorKind};

pub(crate) fn with_canonical_jid<T>(
    text: &str,
    max_len: usize,
    convert: impl for<'a> FnOnce(JidRef<'a>) -> Result<T, StorageError>,
) -> Result<T, StorageError> {
    if text.len() > max_len {
        return Err(StorageError::new(StorageErrorKind::CorruptData));
    }
    let mut arena = Arena::try_new(ArenaConfig::default())
        .map_err(|error| StorageError::with_source(StorageErrorKind::Other, error))?;
    let jid = Jid::parse_in(text, &mut arena).map_err(|error| {
        let kind = match error {
            JidError::AllocationFailed(_) | JidError::AccessFailed(_) => StorageErrorKind::Other,
            _ => StorageErrorKind::CorruptData,
        };
        StorageError::with_source(kind, error)
    })?;
    let jid = jid
        .resolve(&arena)
        .map_err(|error| StorageError::with_source(StorageErrorKind::Other, error))?;
    // Normalizing stored keys would break cursor ordering and hide corruption.
    if jid.as_str() != text {
        return Err(StorageError::new(StorageErrorKind::CorruptData));
    }
    convert(jid)
}
