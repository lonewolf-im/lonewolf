// SPDX-License-Identifier: Apache-2.0

use futures_util::{Stream, stream};

use super::{Account, AccountError, AccountKey, AccountPageSize, AccountRepository};

struct State {
    after: Option<AccountKey>,
    accounts: std::vec::IntoIter<Account>,
    has_more: bool,
}

pub(super) fn accounts<R: AccountRepository + ?Sized>(
    repository: &R,
    after: Option<AccountKey>,
    size: AccountPageSize,
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
            let page = repository.list(state.after.as_ref(), size).await?;
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
