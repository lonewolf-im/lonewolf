// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroUsize;

use futures_executor::block_on;

use super::{TestResult, key, new_account, read, write};
use crate::account::{AccountKey, AccountWrites};
use crate::offline::{
    OfflineError, OfflinePage, OfflineReads, OfflineSequence, OfflineWrites, StoredMessage,
};
use crate::{Storage, WriteTransaction};

async fn create_owners<S: Storage>(storage: &S, owners: &[&str]) -> TestResult {
    let mut writer = storage.begin_write().await?;
    for owner in owners {
        writer.create_account(new_account(owner, 10)?).await?;
    }
    writer.commit().await?;
    Ok(())
}

pub(crate) fn offline_reads_of_an_empty_or_absent_account_return_no_messages<S: Storage>(
    storage: S,
) -> TestResult {
    let owner = key("alice@example.com")?;
    block_on(async {
        let reader = storage.begin_read().await?;
        assert!(reader.offline_messages(&owner).await?.is_empty());
        assert_eq!(reader.offline_count(&owner).await?, 0);
        create_owners(&storage, &["alice@example.com"]).await?;
        let writer = storage.begin_write().await?;
        assert!(writer.offline_messages(&owner).await?.is_empty());
        assert_eq!(writer.offline_count(&owner).await?, 0);
        Ok(())
    })
}

pub(crate) fn offline_messages_keep_every_field_in_sequence_order<S: Storage>(
    storage: S,
) -> TestResult {
    let owner = key("alice@example.com")?;
    let expected = [
        StoredMessage {
            sequence: OfflineSequence::new(1),
            stored_at: 100,
            stanza: Box::from(&b"<message><body>hello</body></message>"[..]),
        },
        StoredMessage {
            sequence: OfflineSequence::new(2),
            stored_at: 90,
            stanza: Box::from(&b"opaque\0\xff"[..]),
        },
        StoredMessage {
            sequence: OfflineSequence::new(3),
            stored_at: u64::MAX,
            stanza: Box::from(&b""[..]),
        },
    ];
    block_on(async {
        let mut writer = storage.begin_write().await?;
        writer
            .create_account(new_account("alice@example.com", 10)?)
            .await?;
        for message in &expected[..2] {
            assert_eq!(
                writer
                    .push_offline_message(&owner, message.stored_at, &message.stanza)
                    .await?,
                message.sequence
            );
        }
        assert_eq!(writer.offline_count(&owner).await?, 2);
        assert_eq!(writer.offline_messages(&owner).await?, expected[..2]);
        let reader = storage.begin_read().await?;
        assert_eq!(reader.offline_count(&owner).await?, 0);
        writer.commit().await?;
        let last = &expected[2];
        assert_eq!(
            write(&storage, async |tx| tx
                .push_offline_message(&owner, last.stored_at, &last.stanza)
                .await)
            .await?,
            last.sequence
        );
        let reader = storage.begin_read().await?;
        assert_eq!(reader.offline_count(&owner).await?, 3);
        assert_eq!(reader.offline_messages(&owner).await?, expected);
        Ok(())
    })
}

pub(crate) fn removing_offline_messages_through_preserves_later_messages_and_the_counter<
    S: Storage,
>(
    storage: S,
) -> TestResult {
    let owner = key("alice@example.com")?;
    block_on(async {
        create_owners(&storage, &["alice@example.com"]).await?;
        let mut writer = storage.begin_write().await?;
        for _ in 0..3 {
            writer
                .push_offline_message(&owner, 100, b"<message/>")
                .await?;
        }
        assert_eq!(
            writer
                .remove_offline_messages_through(&owner, OfflineSequence::new(0))
                .await?,
            0
        );
        assert_eq!(
            writer
                .remove_offline_messages_through(&owner, OfflineSequence::new(2))
                .await?,
            2
        );
        assert_eq!(
            writer
                .remove_offline_messages_through(&owner, OfflineSequence::new(2))
                .await?,
            0
        );
        assert_eq!(writer.offline_count(&owner).await?, 1);
        assert_eq!(writer.offline_messages(&owner).await?[0].sequence.get(), 3);
        assert_eq!(
            writer
                .remove_offline_messages_through(&owner, OfflineSequence::new(u64::MAX))
                .await?,
            1
        );
        writer.commit().await?;
        let mut writer = storage.begin_write().await?;
        assert_eq!(
            writer
                .push_offline_message(&owner, 100, b"<message/>")
                .await?
                .get(),
            4
        );
        assert_eq!(
            writer
                .remove_offline_messages_through(&owner, OfflineSequence::new(3))
                .await?,
            0
        );
        writer.commit().await?;
        assert_eq!(
            read(&storage, async |tx| tx.offline_count(&owner).await).await?,
            1
        );
        Ok(())
    })
}

pub(crate) fn removing_one_offline_message_preserves_other_messages_and_the_counter<S: Storage>(
    storage: S,
) -> TestResult {
    let owner = key("alice@example.com")?;
    block_on(async {
        create_owners(&storage, &["alice@example.com"]).await?;
        let mut writer = storage.begin_write().await?;
        for _ in 0..3 {
            writer
                .push_offline_message(&owner, 100, b"<message/>")
                .await?;
        }
        assert!(
            writer
                .remove_offline_message(&owner, OfflineSequence::new(2))
                .await?
        );
        assert!(
            !writer
                .remove_offline_message(&owner, OfflineSequence::new(2))
                .await?
        );
        let remaining = writer.offline_messages(&owner).await?;
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining[0].sequence.get(), 1);
        assert_eq!(remaining[1].sequence.get(), 3);
        for message in remaining {
            assert!(
                writer
                    .remove_offline_message(&owner, message.sequence)
                    .await?
            );
        }
        writer.commit().await?;
        assert_eq!(
            write(&storage, async |tx| tx
                .push_offline_message(&owner, 100, b"<message/>")
                .await)
            .await?
            .get(),
            4
        );
        Ok(())
    })
}

pub(crate) fn clearing_offline_messages_during_deletion_resets_a_recreated_accounts_counter<
    S: Storage,
>(
    storage: S,
) -> TestResult {
    let owner = key("alice@example.com")?;
    block_on(async {
        create_owners(&storage, &["alice@example.com"]).await?;
        let mut writer = storage.begin_write().await?;
        for _ in 0..2 {
            writer
                .push_offline_message(&owner, 100, b"<message/>")
                .await?;
        }
        writer.commit().await?;
        let mut writer = storage.begin_write().await?;
        writer.delete_account(&owner).await?;
        writer.clear_offline_messages(&owner).await?;
        assert_eq!(writer.offline_count(&owner).await?, 0);
        writer.commit().await?;
        create_owners(&storage, &["alice@example.com"]).await?;
        assert_eq!(
            write(&storage, async |tx| tx
                .push_offline_message(&owner, 100, b"<message/>")
                .await)
            .await?
            .get(),
            1
        );
        Ok(())
    })
}

pub(crate) fn offline_operations_isolate_accounts_with_shared_prefixes<S: Storage>(
    storage: S,
) -> TestResult {
    let a = key("a@x")?;
    let ab = key("ab@x")?;
    let axy = key("a@xy")?;
    block_on(async {
        create_owners(&storage, &["a@x", "ab@x", "a@xy"]).await?;
        let mut writer = storage.begin_write().await?;
        for owner in [&a, &ab, &axy] {
            for sequence in 1..=2 {
                assert_eq!(
                    writer
                        .push_offline_message(owner, sequence, owner.as_str().as_bytes())
                        .await?
                        .get(),
                    sequence
                );
            }
        }
        writer.commit().await?;
        let reader = storage.begin_read().await?;
        for owner in [&a, &ab, &axy] {
            assert_eq!(reader.offline_count(owner).await?, 2);
            assert!(
                reader
                    .offline_messages(owner)
                    .await?
                    .iter()
                    .all(|message| message.stanza.as_ref() == owner.as_str().as_bytes())
            );
        }
        let mut writer = storage.begin_write().await?;
        assert!(
            writer
                .remove_offline_message(&a, OfflineSequence::new(1))
                .await?
        );
        assert_eq!(
            writer
                .remove_offline_messages_through(&a, OfflineSequence::new(2))
                .await?,
            1
        );
        writer.delete_account(&a).await?;
        writer.clear_offline_messages(&a).await?;
        writer.commit().await?;
        let reader = storage.begin_read().await?;
        assert_eq!(reader.offline_count(&a).await?, 0);
        assert_eq!(reader.offline_count(&ab).await?, 2);
        assert_eq!(reader.offline_count(&axy).await?, 2);
        assert_eq!(
            write(&storage, async |tx| tx
                .push_offline_message(&ab, 100, b"<message/>")
                .await)
            .await?
            .get(),
            3
        );
        Ok(())
    })
}

pub(crate) fn offline_push_for_an_absent_or_deleted_account_writes_nothing<S: Storage>(
    storage: S,
) -> TestResult {
    let owner = key("alice@example.com")?;
    block_on(async {
        let mut writer = storage.begin_write().await?;
        assert!(matches!(
            writer
                .push_offline_message(&owner, 100, b"<message/>")
                .await,
            Err(OfflineError::NoAccount)
        ));
        writer.commit().await?;
        create_owners(&storage, &["alice@example.com"]).await?;
        let mut writer = storage.begin_write().await?;
        writer.delete_account(&owner).await?;
        assert!(matches!(
            writer
                .push_offline_message(&owner, 100, b"<message/>")
                .await,
            Err(OfflineError::NoAccount)
        ));
        writer.commit().await?;
        assert_eq!(
            read(&storage, async |tx| tx.offline_count(&owner).await).await?,
            0
        );
        create_owners(&storage, &["alice@example.com"]).await?;
        assert_eq!(
            write(&storage, async |tx| tx
                .push_offline_message(&owner, 100, b"<message/>")
                .await)
            .await?
            .get(),
            1
        );
        Ok(())
    })
}

pub(crate) fn offline_removals_and_clear_succeed_without_messages<S: Storage>(
    storage: S,
) -> TestResult {
    let owner = key("alice@example.com")?;
    block_on(async {
        let mut writer = storage.begin_write().await?;
        assert!(
            !writer
                .remove_offline_message(&owner, OfflineSequence::new(1))
                .await?
        );
        assert_eq!(
            writer
                .remove_offline_messages_through(&owner, OfflineSequence::new(u64::MAX))
                .await?,
            0
        );
        writer.clear_offline_messages(&owner).await?;
        writer.clear_offline_messages(&owner).await?;
        writer.commit().await?;
        Ok(())
    })
}

pub(crate) fn dropping_offline_writes_preserves_messages_and_the_counter<S: Storage>(
    storage: S,
) -> TestResult {
    let owner = key("alice@example.com")?;
    block_on(async {
        create_owners(&storage, &["alice@example.com"]).await?;
        let mut writer = storage.begin_write().await?;
        assert_eq!(
            writer
                .push_offline_message(&owner, 90, b"discarded")
                .await?
                .get(),
            1
        );
        drop(writer);
        assert_eq!(
            read(&storage, async |tx| tx.offline_count(&owner).await).await?,
            0
        );
        let first = write(&storage, async |tx| {
            tx.push_offline_message(&owner, 100, b"retained").await
        })
        .await?;
        assert_eq!(first.get(), 1);
        let mut writer = storage.begin_write().await?;
        assert_eq!(
            writer
                .push_offline_message(&owner, 110, b"discarded")
                .await?
                .get(),
            2
        );
        writer.remove_offline_message(&owner, first).await?;
        writer.delete_account(&owner).await?;
        writer.clear_offline_messages(&owner).await?;
        drop(writer);
        let messages = read(&storage, async |tx| tx.offline_messages(&owner).await).await?;
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].stanza.as_ref(), b"retained");
        assert_eq!(
            write(&storage, async |tx| tx
                .push_offline_message(&owner, 120, b"retained too")
                .await)
            .await?
            .get(),
            2
        );
        Ok(())
    })
}

pub(crate) fn offline_reads_keep_their_snapshot_across_commits<S: Storage>(
    storage: S,
) -> TestResult {
    let owner = key("alice@example.com")?;
    block_on(async {
        create_owners(&storage, &["alice@example.com"]).await?;
        write(&storage, async |tx| {
            tx.push_offline_message(&owner, 100, b"first").await
        })
        .await?;
        let reader = storage.begin_read().await?;
        let mut writer = storage.begin_write().await?;
        writer
            .remove_offline_message(&owner, OfflineSequence::new(1))
            .await?;
        writer.push_offline_message(&owner, 110, b"second").await?;
        writer.commit().await?;
        assert_eq!(reader.offline_count(&owner).await?, 1);
        assert_eq!(
            reader.offline_messages(&owner).await?[0].stanza.as_ref(),
            b"first"
        );
        let current = storage.begin_read().await?;
        assert_eq!(current.offline_count(&owner).await?, 1);
        let messages = current.offline_messages(&owner).await?;
        assert_eq!(messages[0].sequence.get(), 2);
        assert_eq!(messages[0].stanza.as_ref(), b"second");
        Ok(())
    })
}

async fn store_offline_rows<S: Storage>(
    storage: &S,
    owner: &AccountKey,
    records: &[(u64, &[u8])],
) -> TestResult {
    write(storage, async |transaction| {
        for (stored_at, stanza) in records {
            transaction
                .push_offline_message(owner, *stored_at, stanza)
                .await?;
        }
        Ok::<_, OfflineError>(())
    })
    .await
}

fn page_sequences(page: &OfflinePage) -> Vec<u64> {
    page.iter().map(|(entry, _)| entry.sequence.get()).collect()
}

pub(crate) fn offline_pages_follow_sequence_order_and_keep_every_field<S: Storage>(
    storage: S,
) -> TestResult {
    let owner = key("alice@example.com")?;
    let expected: [(u64, &[u8]); 3] = [
        (100, b"<message><body>hello</body></message>"),
        (90, b"opaque\0\xff"),
        (u64::MAX, b""),
    ];
    block_on(async {
        create_owners(&storage, &["alice@example.com"]).await?;
        store_offline_rows(&storage, &owner, &expected).await?;
        let page = storage
            .begin_read()
            .await?
            .offline_page(
                &owner,
                None,
                OfflineSequence::new(3),
                NonZeroUsize::new(100).ok_or("invalid byte limit")?,
                OfflinePage::new(),
            )
            .await?;
        assert!(page.is_complete());
        assert_eq!(page_sequences(&page), vec![1, 2, 3]);
        assert!(
            page.iter()
                .map(|(entry, stanza)| (entry.stored_at, stanza))
                .eq(expected)
        );
        Ok(())
    })
}

pub(crate) fn offline_pages_stop_before_the_message_that_exceeds_the_byte_limit<S: Storage>(
    storage: S,
) -> TestResult {
    let owner = key("alice@example.com")?;
    block_on(async {
        create_owners(&storage, &["alice@example.com"]).await?;
        store_offline_rows(&storage, &owner, &[(0, b"0123456789".as_slice()); 3]).await?;
        let limit = NonZeroUsize::new(20).ok_or("invalid byte limit")?;
        let transaction = storage.begin_read().await?;
        let through = OfflineSequence::new(3);
        let first = transaction
            .offline_page(&owner, None, through, limit, OfflinePage::new())
            .await?;
        assert_eq!(page_sequences(&first), vec![1, 2]);
        assert_eq!(first.byte_len(), 20);
        assert!(!first.is_complete());
        let after = first.resume_after().map(|entry| entry.sequence);
        let second = transaction
            .offline_page(&owner, after, through, limit, first)
            .await?;
        assert_eq!(page_sequences(&second), vec![3]);
        assert_eq!(second.byte_len(), 10);
        assert!(second.is_complete());
        Ok(())
    })
}

pub(crate) fn an_oversized_message_fills_a_page_by_itself<S: Storage>(storage: S) -> TestResult {
    let owner = key("alice@example.com")?;
    block_on(async {
        create_owners(&storage, &["alice@example.com"]).await?;
        store_offline_rows(&storage, &owner, &[(1, b"oversized"), (2, b"x")]).await?;
        let transaction = storage.begin_read().await?;
        let through = OfflineSequence::new(2);
        let first = transaction
            .offline_page(&owner, None, through, NonZeroUsize::MIN, OfflinePage::new())
            .await?;
        assert_eq!(page_sequences(&first), vec![1]);
        assert_eq!(first.byte_len(), b"oversized".len());
        assert!(!first.is_complete());
        let after = first.resume_after().map(|entry| entry.sequence);
        let second = transaction
            .offline_page(&owner, after, through, NonZeroUsize::MIN, first)
            .await?;
        assert_eq!(page_sequences(&second), vec![2]);
        assert!(second.is_complete());
        Ok(())
    })
}

pub(crate) fn offline_pages_resume_after_the_cursor_and_stop_at_the_watermark<S: Storage>(
    storage: S,
) -> TestResult {
    let owner = key("alice@example.com")?;
    block_on(async {
        create_owners(&storage, &["alice@example.com"]).await?;
        store_offline_rows(&storage, &owner, &[(0, b"x".as_slice()); 5]).await?;
        let transaction = storage.begin_read().await?;
        let through = OfflineSequence::new(4);
        let limit = NonZeroUsize::new(8).ok_or("invalid byte limit")?;
        let page = transaction
            .offline_page(
                &owner,
                Some(OfflineSequence::new(2)),
                through,
                limit,
                OfflinePage::new(),
            )
            .await?;
        assert_eq!(page_sequences(&page), vec![3, 4]);
        assert!(page.is_complete());
        for after in [through, OfflineSequence::new(u64::MAX)] {
            let empty = transaction
                .offline_page(&owner, Some(after), through, limit, OfflinePage::new())
                .await?;
            assert!(empty.is_empty());
            assert!(empty.is_complete());
        }
        Ok(())
    })
}

pub(crate) fn offline_pages_skip_removed_messages_and_isolate_shared_prefixes<S: Storage>(
    storage: S,
) -> TestResult {
    let a = key("a@x")?;
    let ab = key("ab@x")?;
    let axy = key("a@xy")?;
    block_on(async {
        create_owners(&storage, &["a@x", "ab@x", "a@xy"]).await?;
        store_offline_rows(&storage, &a, &[(0, b"a".as_slice()); 3]).await?;
        store_offline_rows(&storage, &ab, &[(0, b"ab")]).await?;
        store_offline_rows(&storage, &axy, &[(0, b"axy")]).await?;
        let mut transaction = storage.begin_write().await?;
        assert!(
            transaction
                .remove_offline_message(&a, OfflineSequence::new(2))
                .await?
        );
        let page = transaction
            .offline_page(
                &a,
                None,
                OfflineSequence::new(u64::MAX),
                NonZeroUsize::new(8).ok_or("invalid byte limit")?,
                OfflinePage::new(),
            )
            .await?;
        assert!(page.is_complete());
        assert_eq!(page_sequences(&page), vec![1, 3]);
        assert!(page.iter().all(|(_, stanza)| stanza == b"a"));
        Ok(())
    })
}

pub(crate) fn last_offline_sequence_reports_the_highest_stored_message<S: Storage>(
    storage: S,
) -> TestResult {
    let owner = key("alice@example.com")?;
    block_on(async {
        create_owners(&storage, &["alice@example.com"]).await?;
        let mut transaction = storage.begin_write().await?;
        assert_eq!(transaction.last_offline_sequence(&owner).await?, None);
        let first = transaction
            .push_offline_message(&owner, 0, b"first")
            .await?;
        let second = transaction
            .push_offline_message(&owner, 0, b"second")
            .await?;
        assert_eq!(
            transaction.last_offline_sequence(&owner).await?,
            Some(second)
        );
        assert!(transaction.remove_offline_message(&owner, second).await?);
        assert_eq!(
            transaction.last_offline_sequence(&owner).await?,
            Some(first)
        );
        assert_eq!(
            transaction
                .remove_offline_messages_through(&owner, first)
                .await?,
            1
        );
        assert_eq!(transaction.last_offline_sequence(&owner).await?, None);
        Ok(())
    })
}

pub(crate) fn offline_pages_read_their_transaction_snapshot<S: Storage>(storage: S) -> TestResult {
    let owner = key("alice@example.com")?;
    block_on(async {
        create_owners(&storage, &["alice@example.com"]).await?;
        store_offline_rows(&storage, &owner, &[(1, b"first")]).await?;
        let snapshot = storage.begin_read().await?;
        store_offline_rows(&storage, &owner, &[(2, b"second")]).await?;
        assert_eq!(
            snapshot.last_offline_sequence(&owner).await?,
            Some(OfflineSequence::new(1))
        );
        let through = OfflineSequence::new(2);
        let limit = NonZeroUsize::new(32).ok_or("invalid byte limit")?;
        let page = snapshot
            .offline_page(&owner, None, through, limit, OfflinePage::new())
            .await?;
        assert!(page.is_complete());
        assert_eq!(page_sequences(&page), vec![1]);
        let page = storage
            .begin_read()
            .await?
            .offline_page(&owner, None, through, limit, page)
            .await?;
        assert!(page.is_complete());
        assert_eq!(page_sequences(&page), vec![1, 2]);
        Ok(())
    })
}
