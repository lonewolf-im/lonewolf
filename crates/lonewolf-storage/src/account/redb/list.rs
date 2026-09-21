// SPDX-License-Identifier: Apache-2.0

use std::ops::Bound;

use futures_util::{Stream, stream};
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_xmpp::jid::{Jid, JidError, MAX_PART_LEN};
use redb::{Database, ReadableDatabase};

use crate::account::{Account, AccountError, AccountKey, AccountPageSize};
use crate::redb::storage_error;
use crate::{RedbDatabase, StorageError, StorageErrorKind};

use super::{ACCOUNTS, decode_credentials};

struct Page {
    accounts: Vec<Account>,
    has_more: bool,
}

struct State {
    after: Option<AccountKey>,
    accounts: std::vec::IntoIter<Account>,
    has_more: bool,
}

pub(super) fn accounts(
    database: &RedbDatabase,
    after: Option<AccountKey>,
    batch_size: AccountPageSize,
) -> impl Stream<Item = Result<Account, AccountError>> {
    let state = State {
        after,
        accounts: Vec::new().into_iter(),
        has_more: true,
    };
    stream::try_unfold(state, move |mut state| async move {
        if state.accounts.len() == 0 {
            if !state.has_more {
                return Ok(None);
            }
            drop(state.accounts);
            let after = state.after.take();
            let page = database
                .read(move |database| read_page(database, after, batch_size))
                .await?;
            state.after = page
                .accounts
                .last()
                .filter(|_| page.has_more)
                .map(|account| account.key.clone());
            state.has_more = page.has_more;
            state.accounts = page.accounts.into_iter();
        }
        Ok(state.accounts.next().map(|account| (account, state)))
    })
}

fn read_page(
    database: &Database,
    after: Option<AccountKey>,
    batch_size: AccountPageSize,
) -> Result<Page, AccountError> {
    let transaction = database.begin_read().map_err(storage_error)?;
    let table = transaction.open_table(ACCOUNTS).map_err(storage_error)?;
    let start = after
        .as_ref()
        .map_or(Bound::Unbounded, |key| Bound::Excluded(key.as_str()));
    let mut entries = table
        .range::<&str>((start, Bound::Unbounded))
        .map_err(storage_error)?;
    let mut accounts = Vec::with_capacity(batch_size.get());
    let mut arena = Arena::try_new(ArenaConfig::default())
        .map_err(|error| StorageError::with_source(StorageErrorKind::Other, error))?;
    for entry in entries.by_ref().take(batch_size.get()) {
        let (key, record) = entry.map_err(storage_error)?;
        decode_credentials(record.value())?;
        accounts.push(Account {
            key: decode_account_key(key.value(), &mut arena)?,
        });
    }
    let has_more = entries.next().transpose().map_err(storage_error)?.is_some();
    Ok(Page { accounts, has_more })
}

fn decode_account_key(text: &str, arena: &mut Arena) -> Result<AccountKey, StorageError> {
    if text.len() > MAX_PART_LEN * 2 + 1 {
        return Err(StorageError::new(StorageErrorKind::CorruptData));
    }
    let jid = Jid::parse_in(text, arena).map_err(|error| {
        let kind = match error {
            JidError::AllocationFailed(_) | JidError::AccessFailed(_) => StorageErrorKind::Other,
            _ => StorageErrorKind::CorruptData,
        };
        StorageError::with_source(kind, error)
    })?;
    let jid = jid
        .resolve(arena)
        .map_err(|error| StorageError::with_source(StorageErrorKind::Other, error))?;
    if jid.as_str() != text {
        return Err(StorageError::new(StorageErrorKind::CorruptData));
    }
    AccountKey::try_from(jid)
        .map_err(|error| StorageError::with_source(StorageErrorKind::CorruptData, error))
}
