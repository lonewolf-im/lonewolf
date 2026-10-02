// SPDX-License-Identifier: Apache-2.0

use futures_executor::block_on;

use super::{TestResult, key, new_account, read, write};
use crate::account::AccountWrites;
use crate::offline::{OfflineError, OfflineReads, OfflineSequence, OfflineWrites, StoredMessage};
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
