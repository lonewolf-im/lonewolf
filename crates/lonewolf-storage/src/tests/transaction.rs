// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::num::NonZeroUsize;
use std::thread;

use futures_executor::block_on;
use lonewolf_auth::scram::ScramHash;

use super::{
    TestResult, assert_scram, credentials, decoy_salt, item, jid, key, new_account, pending, poll,
    read, write,
};
use crate::account::{AccountReads, AccountWrites};
use crate::roster::{RosterReads, RosterWrites};
use crate::{Storage, WriteTransaction};

pub(crate) fn uncommitted_writes_are_visible_only_inside_their_transaction<S: Storage>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let bob = jid("bob@example.com")?;
    let bob_item = item("bob@example.com", Some("Bob"), &[])?;
    block_on(async {
        let mut writer = storage.begin_write().await?;
        writer
            .create_account(new_account("alice@example.com", 10)?)
            .await?;
        let version = writer.put_roster_item(&alice, &bob_item).await?;
        writer
            .put_pending_request(
                &alice,
                pending("bob@example.com", b"<presence/>")?,
                std::num::NonZeroUsize::MAX,
            )
            .await?;
        assert!(writer.account(&alice).await?.is_some());
        assert_eq!(
            writer.accounts_after(None, NonZeroUsize::MAX).await?.len(),
            1
        );
        assert_eq!(writer.roster(&alice).await?.version, version);
        assert_eq!(writer.roster_item(&alice, &bob).await?, Some(bob_item));
        assert_eq!(writer.pending_requests(&alice).await?.len(), 1);
        assert!(writer.pending_request(&alice, &bob).await?.is_some());

        let reader = storage.begin_read().await?;
        assert!(reader.account(&alice).await?.is_none());
        assert!(
            reader
                .accounts_after(None, NonZeroUsize::MAX)
                .await?
                .is_empty()
        );
        assert_eq!(reader.roster(&alice).await?.version.get(), 0);
        assert!(reader.roster_item(&alice, &bob).await?.is_none());
        assert!(reader.pending_requests(&alice).await?.is_empty());
        assert!(reader.pending_request(&alice, &bob).await?.is_none());

        writer.commit().await?;
        assert!(reader.account(&alice).await?.is_none());
        let reader = storage.begin_read().await?;
        assert!(reader.account(&alice).await?.is_some());
        assert_eq!(reader.roster(&alice).await?.version.get(), 1);
        assert!(reader.pending_request(&alice, &bob).await?.is_some());
        Ok(())
    })
}

pub(crate) fn dropping_a_write_transaction_aborts_every_write<S: Storage>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let bob = key("bob@example.com")?;
    let bob_jid = jid("bob@example.com")?;
    block_on(async {
        let mut writer = storage.begin_write().await?;
        writer
            .create_account(new_account("alice@example.com", 10)?)
            .await?;
        writer
            .put_roster_item(&alice, &item("bob@example.com", None, &[])?)
            .await?;
        writer.commit().await?;

        let mut writer = storage.begin_write().await?;
        writer.delete_account(&alice).await?;
        writer.clear_roster(&alice).await?;
        writer
            .create_account(new_account("bob@example.com", 20)?)
            .await?;
        writer
            .put_roster_item(&bob, &item("alice@example.com", None, &[])?)
            .await?;
        writer
            .put_pending_request(
                &bob,
                pending("alice@example.com", b"<presence/>")?,
                std::num::NonZeroUsize::MAX,
            )
            .await?;
        assert!(writer.account(&alice).await?.is_none());
        assert!(writer.account(&bob).await?.is_some());
        drop(writer);

        let reader = storage.begin_read().await?;
        assert!(reader.account(&alice).await?.is_some());
        assert_eq!(reader.roster(&alice).await?.version.get(), 1);
        assert!(reader.roster_item(&alice, &bob_jid).await?.is_some());
        assert!(reader.account(&bob).await?.is_none());
        assert_eq!(reader.roster(&bob).await?.version.get(), 0);
        assert!(reader.pending_requests(&bob).await?.is_empty());
        Ok(())
    })
}

pub(crate) fn commit_persists_account_and_roster_writes_together<S: Storage>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let carol = key("carol@example.com")?;
    block_on(async {
        let mut writer = storage.begin_write().await?;
        for owner in ["alice@example.com", "carol@example.com"] {
            writer.create_account(new_account(owner, 10)?).await?;
            writer
                .put_roster_item(&key(owner)?, &item("bob@example.com", None, &[])?)
                .await?;
            writer
                .put_pending_request(
                    &key(owner)?,
                    pending("bob@example.com", b"<presence/>")?,
                    std::num::NonZeroUsize::MAX,
                )
                .await?;
        }
        writer.commit().await?;

        let mut writer = storage.begin_write().await?;
        writer.delete_account(&alice).await?;
        writer.clear_roster(&alice).await?;
        writer.commit().await?;

        let reader = storage.begin_read().await?;
        assert!(reader.account(&alice).await?.is_none());
        let cleared = reader.roster(&alice).await?;
        assert_eq!(cleared.version.get(), 0);
        assert!(cleared.items.is_empty());
        assert!(reader.pending_requests(&alice).await?.is_empty());
        assert!(reader.account(&carol).await?.is_some());
        assert_eq!(reader.roster(&carol).await?.items.len(), 1);
        assert_eq!(reader.pending_requests(&carol).await?.len(), 1);
        Ok(())
    })
}

pub(crate) fn a_read_transaction_keeps_its_snapshot_across_commits<S: Storage>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let account = new_account("alice@example.com", 10)?;
    let update = item("bob@example.com", None, &[])?;
    block_on(async {
        write(&storage, async |tx| tx.create_account(account).await).await?;
        let reader = storage.begin_read().await?;

        let mut writer = storage.begin_write().await?;
        writer.replace_credentials(&alice, credentials(20)).await?;
        writer.put_roster_item(&alice, &update).await?;
        writer.commit().await?;

        assert_scram(reader.scram(&alice, ScramHash::Sha256).await?, 13)?;
        assert_eq!(reader.roster(&alice).await?.version.get(), 0);
        let current = storage.begin_read().await?;
        assert_scram(current.scram(&alice, ScramHash::Sha256).await?, 23)?;
        assert_eq!(current.roster(&alice).await?.version.get(), 1);
        Ok(())
    })
}

pub(crate) fn a_second_write_transaction_waits_for_the_first_while_reads_proceed<S: Storage>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let account = new_account("alice@example.com", 10)?;
    block_on(async {
        let mut first = storage.begin_write().await?;
        first.create_account(account).await?;
        let mut second = Box::pin(storage.begin_write());
        assert!(poll(second.as_mut()).is_pending());
        assert!(
            read(&storage, async |tx| tx.account(&alice).await)
                .await?
                .is_none()
        );
        assert!(poll(second.as_mut()).is_pending());

        first.commit().await?;
        let mut second = second.await?;
        assert!(second.account(&alice).await?.is_some());
        second.delete_account(&alice).await?;
        let mut third = Box::pin(storage.begin_write());
        assert!(poll(third.as_mut()).is_pending());
        drop(second);
        let third = third.await?;
        assert!(third.account(&alice).await?.is_some());
        Ok(())
    })
}

pub(crate) fn cancelling_a_waiting_write_transaction_does_not_block_later_writers<S: Storage>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let account = new_account("alice@example.com", 10)?;
    block_on(async {
        let first = storage.begin_write().await?;
        let mut waiting = Box::pin(storage.begin_write());
        assert!(poll(waiting.as_mut()).is_pending());
        drop(waiting);
        let mut next = Box::pin(storage.begin_write());
        assert!(poll(next.as_mut()).is_pending());
        drop(first);

        let mut next = next.await?;
        next.create_account(account).await?;
        next.commit().await?;
        assert!(
            read(&storage, async |tx| tx.account(&alice).await)
                .await?
                .is_some()
        );
        storage.begin_write().await?.commit().await?;
        Ok(())
    })
}

pub(crate) fn transactions_can_be_driven_from_other_threads<S: Storage>(storage: S) -> TestResult {
    fn assert_send_sync<T: Send + Sync>() {}

    fn on_worker<F>(future: F) -> TestResult<F::Output>
    where
        F: Future + Send,
        F::Output: Send,
    {
        thread::scope(|scope| {
            scope
                .spawn(move || block_on(future))
                .join()
                .map_err(|_| "storage worker panicked".into())
        })
    }

    assert_send_sync::<S>();
    assert_send_sync::<S::Read>();
    assert_send_sync::<S::Write>();
    let alice = key("alice@example.com")?;
    let bob = item("bob@example.com", None, &[])?;
    let mut writer = on_worker(storage.begin_write())??;
    on_worker(writer.create_account(new_account("alice@example.com", 10)?))??;
    on_worker(writer.replace_credentials(&alice, credentials(20)))??;
    assert_scram(on_worker(writer.scram(&alice, ScramHash::Sha256))??, 23)?;
    on_worker(writer.put_roster_item(&alice, &bob))??;
    on_worker(writer.commit())??;

    let reader = on_worker(storage.begin_read())??;
    assert_eq!(
        on_worker(reader.account(&alice))??
            .ok_or("missing account")?
            .key,
        alice
    );
    assert_eq!(
        on_worker(reader.accounts_after(None, NonZeroUsize::MAX))??.len(),
        1
    );
    assert_eq!(on_worker(reader.roster(&alice))??.items.len(), 1);
    Ok(())
}

pub(crate) fn clones_share_committed_state_and_the_scram_decoy<S: Storage>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let account = new_account("alice@example.com", 10)?;
    let cloned = storage.clone();
    assert_eq!(
        decoy_salt(cloned.scram_decoy())?,
        decoy_salt(storage.scram_decoy())?
    );
    block_on(async {
        write(&storage, async |tx| tx.create_account(account).await).await?;
        write(&cloned, async |tx| {
            tx.replace_credentials(&alice, credentials(20)).await
        })
        .await?;
        assert_scram(
            read(&storage, async |tx| {
                tx.scram(&alice, ScramHash::Sha256).await
            })
            .await?,
            23,
        )?;
        drop(storage);
        assert_scram(
            read(&cloned, async |tx| tx.scram(&alice, ScramHash::Sha1).await).await?,
            20,
        )?;
        Ok(())
    })
}
