// SPDX-License-Identifier: Apache-2.0

use std::ops::Bound;

use futures_util::{Stream, stream};
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_xmpp::jid::{Jid, JidError, MAX_PART_LEN};
use redb::{Database, OwnedRange, ReadableDatabase};

use crate::account::{Account, AccountError, AccountKey};
use crate::redb::storage_error;
use crate::{RedbDatabase, StorageError, StorageErrorKind};

use super::{ACCOUNTS, decode_credentials};

struct State {
    after: Option<AccountKey>,
    entries: Option<OwnedRange<&'static str, &'static [u8]>>,
}

pub(super) fn accounts(
    database: &RedbDatabase,
    after: Option<AccountKey>,
) -> impl Stream<Item = Result<Account, AccountError>> {
    let state = State {
        after,
        entries: None,
    };
    stream::try_unfold(state, move |state| async move {
        database
            .read(move |database| {
                let mut entries = match state.entries {
                    Some(entries) => entries,
                    None => open_range(database, state.after)?,
                };
                let Some(entry) = entries.next() else {
                    return Ok(None);
                };
                let (key, record) = entry.map_err(storage_error)?;
                decode_credentials(record.value())?;
                let account = Account {
                    key: decode_account_key(key.value())?,
                };
                Ok(Some((
                    account,
                    State {
                        after: None,
                        entries: Some(entries),
                    },
                )))
            })
            .await
    })
}

fn open_range(
    database: &Database,
    after: Option<AccountKey>,
) -> Result<OwnedRange<&'static str, &'static [u8]>, AccountError> {
    let transaction = database.begin_read().map_err(storage_error)?;
    let table = transaction.open_table(ACCOUNTS).map_err(storage_error)?;
    let start = after
        .as_ref()
        .map_or(Bound::Unbounded, |key| Bound::Excluded(key.as_str()));
    table
        .range_owned::<&str>((start, Bound::Unbounded))
        .map_err(|error| storage_error(error).into())
}

fn decode_account_key(text: &str) -> Result<AccountKey, StorageError> {
    if text.len() > MAX_PART_LEN * 2 + 1 {
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
    if jid.as_str() != text {
        return Err(StorageError::new(StorageErrorKind::CorruptData));
    }
    AccountKey::try_from(jid)
        .map_err(|error| StorageError::with_source(StorageErrorKind::CorruptData, error))
}
