// SPDX-License-Identifier: Apache-2.0

use crate::roster::RosterQuota;

use std::error::Error;

use ::redb::ReadableDatabase;
use futures_executor::block_on;
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_xmpp::jid::Jid;

use super::redb::ITEMS;
use super::{RosterJid, RosterReads, RosterWrites};
use crate::account::AccountWrites;
use crate::redb::tests::storage;
use crate::tests::{TestResult, assert_storage_error, item, jid, key, new_account, read, write};
use crate::{RedbStorage, Storage, StorageErrorKind, WriteTransaction};

const ITEM_KEY: &str = "alice@example.com\0bob@example.com";

fn insert_item(storage: &RedbStorage, key: &str, bytes: &[u8]) -> TestResult {
    let transaction = storage.as_ref().begin_write()?;
    transaction.open_table(ITEMS)?.insert(key, bytes)?;
    transaction.commit()?;
    Ok(())
}

fn remove_item(storage: &RedbStorage, key: &str) -> TestResult {
    let transaction = storage.as_ref().begin_write()?;
    transaction.open_table(ITEMS)?.remove(key)?;
    transaction.commit()?;
    Ok(())
}

fn stored_item(storage: &RedbStorage, key: &str) -> TestResult<Option<Vec<u8>>> {
    let transaction = storage.as_ref().begin_read()?;
    let table = transaction.open_table(ITEMS)?;
    Ok(table.get(key)?.map(|record| record.value().to_vec()))
}

#[test]
fn roster_jids_are_owned_normalized_addresses() -> TestResult {
    let normalized = jid("É@BÜCHER.EXAMPLE")?;
    assert_eq!(normalized, jid("E\u{301}@xn--bcher-kva.example")?);
    assert_eq!(normalized.as_str(), "é@bücher.example");
    assert_eq!(format!("{normalized:?}"), "RosterJid { .. }");

    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let full = Jid::parse_in("alice@example.com/desktop", &mut arena)?;
    assert_eq!(
        RosterJid::from(full.resolve(&arena)?).as_str(),
        "alice@example.com/desktop"
    );
    assert_eq!(jid("example.com")?.as_str(), "example.com");
    Ok(())
}

#[test]
fn canonical_domain_and_resource_roster_keys_survive_storage_reads() -> TestResult {
    let storage = storage()?;
    let alice = key("alice@example.com")?;
    let account = new_account("alice@example.com", 10)?;
    block_on(write(&storage, async |tx| {
        tx.create_account(account).await?;
        for contact in ["example.com", "bob@example.com/desktop"] {
            tx.put_roster_item(&alice, &item(contact, None, &[])?, RosterQuota::default())
                .await?;
        }
        Ok::<(), Box<dyn Error>>(())
    }))?;
    let snapshot = block_on(read(&storage, async |tx| {
        tx.roster(&alice, RosterQuota::default()).await
    }))?;
    assert_eq!(snapshot.items.len(), 2);
    assert_eq!(snapshot.items[0].jid.as_str(), "bob@example.com/desktop");
    assert_eq!(snapshot.items[1].jid.as_str(), "example.com");
    Ok(())
}

#[test]
fn malformed_item_records_fail_operations_and_stay_unchanged_when_the_transaction_is_dropped()
-> TestResult {
    let storage = storage()?;
    let alice = key("alice@example.com")?;
    let bob = jid("bob@example.com")?;
    for bytes in [
        &[][..],
        &[4, 0],
        &[0, 4],
        &[0, 0, 1, 0, 0, 0],
        &[0, 0, 1, 0, 0, 0, 0xff, 0, 0, 0, 0],
        &[0, 0, 255, 255, 255, 255, 1, 0, 0, 0],
        &[0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 1],
    ] {
        insert_item(&storage, ITEM_KEY, bytes)?;
        block_on(async {
            let mut writer = storage.begin_write().await?;
            assert_storage_error(
                writer.roster(&alice, RosterQuota::default()).await,
                StorageErrorKind::CorruptData,
            );
            assert_storage_error(
                writer
                    .roster_item(&alice, &bob, RosterQuota::default())
                    .await,
                StorageErrorKind::CorruptData,
            );
            assert_storage_error(
                writer.remove_roster_item(&alice, &bob).await,
                StorageErrorKind::CorruptData,
            );
            Ok::<(), Box<dyn Error>>(())
        })?;
        assert_eq!(stored_item(&storage, ITEM_KEY)?.as_deref(), Some(bytes));
    }
    Ok(())
}

#[test]
fn noncanonical_item_keys_are_rejected_when_reading_a_roster() -> TestResult {
    let storage = storage()?;
    let alice = key("alice@example.com")?;
    let account = new_account("alice@example.com", 10)?;
    let update = item("bob@example.com", None, &[])?;
    block_on(write(&storage, async |tx| {
        tx.create_account(account).await?;
        tx.put_roster_item(&alice, &update, RosterQuota::default())
            .await?;
        Ok::<(), Box<dyn Error>>(())
    }))?;
    let record = stored_item(&storage, ITEM_KEY)?.ok_or("missing item")?;
    for invalid in [
        "alice@example.com\0",
        "alice@example.com\0BOB@example.com",
        "alice@example.com\0bob@@example.com",
    ] {
        insert_item(&storage, invalid, &record)?;
        block_on(async {
            let reader = storage.begin_read().await?;
            assert_storage_error(
                reader.roster(&alice, RosterQuota::default()).await,
                StorageErrorKind::CorruptData,
            );
            Ok::<(), Box<dyn Error>>(())
        })?;
        remove_item(&storage, invalid)?;
    }
    let snapshot = block_on(read(&storage, async |tx| {
        tx.roster(&alice, RosterQuota::default()).await
    }))?;
    assert_eq!(snapshot.items.len(), 1);
    Ok(())
}

fn quota(items: usize, bytes: usize) -> super::RosterQuota {
    super::RosterQuota {
        max_items: std::num::NonZeroUsize::new(items).unwrap(),
        max_bytes: std::num::NonZeroUsize::new(bytes).unwrap(),
    }
}

#[test]
fn roster_quota_rejects_new_item_without_advancing_version() -> TestResult {
    let storage = storage()?;
    let owner = key("alice@example.com")?;
    block_on(async {
        let mut tx = storage.begin_write().await?;
        tx.create_account(new_account(owner.as_str(), 10)?).await?;
        let limit = quota(2, 1024);
        for contact in ["bob@example.com", "carol@example.com"] {
            tx.put_roster_item(&owner, &item(contact, None, &[])?, limit)
                .await?;
        }
        assert!(matches!(
            tx.put_roster_item(&owner, &item("dave@example.com", None, &[])?, limit)
                .await,
            Err(super::RosterError::QuotaExceeded)
        ));
        assert_eq!(tx.roster_version(&owner).await?.get(), 2);
        assert_eq!(tx.roster(&owner, limit).await?.items.len(), 2);
        tx.commit().await?;
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn roster_quota_counts_encoded_key_and_value_bytes() -> TestResult {
    let storage = storage()?;
    let owner = key("alice@example.com")?;
    block_on(async {
        let mut tx = storage.begin_write().await?;
        tx.create_account(new_account(owner.as_str(), 10)?).await?;
        let contact = item("bob@example.com", Some("Bob"), &["Friends"])?;
        let encoded_len = 10 + 3 + 4 + 7;
        let exact = owner.as_str().len() + 1 + contact.jid.as_str().len() + encoded_len;
        assert!(matches!(
            tx.put_roster_item(&owner, &contact, quota(10, exact - 1))
                .await,
            Err(super::RosterError::QuotaExceeded)
        ));
        tx.put_roster_item(&owner, &contact, quota(10, exact))
            .await?;
        assert!(matches!(
            tx.put_roster_item(
                &owner,
                &item("carol@example.com", None, &[])?,
                quota(10, exact)
            )
            .await,
            Err(super::RosterError::QuotaExceeded)
        ));
        assert_eq!(tx.roster_version(&owner).await?.get(), 1);
        tx.commit().await?;
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn roster_quota_replacement_and_removal_release_usage() -> TestResult {
    let storage = storage()?;
    let owner = key("alice@example.com")?;
    block_on(async {
        let mut tx = storage.begin_write().await?;
        tx.create_account(new_account(owner.as_str(), 10)?).await?;
        let original = item("bob@example.com", Some(&"x".repeat(100)), &[])?;
        tx.put_roster_item(&owner, &original, quota(2, 1024))
            .await?;
        let smaller = item("bob@example.com", None, &[])?;
        tx.put_roster_item(&owner, &smaller, quota(1, 1)).await?;
        assert!(matches!(
            tx.put_roster_item(&owner, &original, quota(1, 1)).await,
            Err(super::RosterError::QuotaExceeded)
        ));
        let limit = quota(1, 80);
        tx.remove_roster_subscription(&owner, &smaller.jid)
            .await?
            .ok_or("missing item")?;
        tx.put_roster_item(&owner, &item("carol@example.com", None, &[])?, limit)
            .await?;
        assert_eq!(tx.roster_version(&owner).await?.get(), 4);
        tx.commit().await?;
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn legacy_snapshot_checks_raw_limits_before_decoding_and_allows_targeted_removal() -> TestResult {
    let storage = storage()?;
    let owner = key("alice@example.com")?;
    let good = [0, 0, 255, 255, 255, 255, 0, 0, 0, 0];
    insert_item(&storage, ITEM_KEY, &good)?;
    insert_item(
        &storage,
        "alice@example.com\0carol@example.com",
        &[255; 100],
    )?;
    block_on(async {
        let mut tx = storage.begin_write().await?;
        assert!(matches!(
            tx.roster(&owner, quota(1, 1024)).await,
            Err(super::RosterError::QuotaExceeded)
        ));
        assert!(matches!(
            tx.roster(&owner, quota(10, 35)).await,
            Err(super::RosterError::QuotaExceeded)
        ));
        tx.remove_roster_subscription(&owner, &jid("carol@example.com")?)
            .await
            .err()
            .ok_or("invalid header was accepted")?;
        Ok::<_, Box<dyn Error>>(())
    })?;
    insert_item(&storage, "alice@example.com\0carol@example.com", &[0, 0])?;
    block_on(async {
        let mut tx = storage.begin_write().await?;
        assert_eq!(
            tx.next_roster_subscription(&owner, None)
                .await?
                .ok_or("missing")?
                .0,
            jid("bob@example.com")?
        );
        tx.remove_roster_subscription(&owner, &jid("carol@example.com")?)
            .await?
            .ok_or("missing")?;
        assert_eq!(tx.roster(&owner, quota(1, 100)).await?.items.len(), 1);
        tx.commit().await?;
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn snapshot_subscription_replacement_preserves_legacy_metadata_and_rejects_stale_data() -> TestResult
{
    use super::{RosterQuota, RosterSubscription, SubscriptionState};
    let storage = storage()?;
    let owner = key("alice@example.com")?;
    let contact = jid("bob@example.com")?;
    let original = item(contact.as_str(), Some(&"x".repeat(8192)), &[])?;
    block_on(write(&storage, async |tx| {
        tx.create_account(new_account(owner.as_str(), 10)?).await?;
        tx.put_roster_item(&owner, &original, RosterQuota::default())
            .await?;
        Ok::<_, Box<dyn Error>>(())
    }))?;
    let raw = stored_item(&storage, ITEM_KEY)?.ok_or("missing")?;
    block_on(async {
        let mut tx = storage.begin_write().await?;
        let before = storage.begin_read().await?;
        let changed = RosterSubscription {
            state: SubscriptionState::Both,
            pending_out: true,
            approved: true,
        };
        assert_eq!(
            tx.set_roster_subscription(&before, &owner, &contact, original.subscription)
                .await?,
            None
        );
        assert_eq!(
            tx.set_roster_subscription(&before, &owner, &jid("missing@example.com")?, changed)
                .await?,
            None
        );
        assert_eq!(
            tx.set_roster_subscription(&before, &owner, &contact, changed)
                .await?
                .ok_or("missing change")?
                .get(),
            2
        );
        tx.commit().await?;
        Ok::<_, Box<dyn Error>>(())
    })?;
    let updated = stored_item(&storage, ITEM_KEY)?.ok_or("missing")?;
    assert_eq!(&updated[2..], &raw[2..]);
    assert_eq!(&updated[..2], &[3, 3]);
    for stale_metadata in [false, true] {
        block_on(async {
            let mut tx = storage.begin_write().await?;
            let before = storage.begin_read().await?;
            let mut current = original.clone();
            current.subscription = RosterSubscription {
                state: SubscriptionState::Both,
                pending_out: true,
                approved: true,
            };
            if stale_metadata {
                current.name = Some("y".repeat(8192).into_boxed_str());
            } else {
                current.subscription.approved = false;
            }
            tx.put_roster_item(&owner, &current, RosterQuota::default())
                .await?;
            assert!(matches!(
                tx.set_roster_subscription(
                    &before,
                    &owner,
                    &contact,
                    RosterSubscription::default()
                )
                .await,
                Err(super::RosterError::Storage(_))
            ));
            assert_eq!(tx.roster_version(&owner).await?.get(), 3);
            Ok::<_, Box<dyn Error>>(())
        })?;
        assert_eq!(stored_item(&storage, ITEM_KEY)?.ok_or("missing")?, updated);
    }
    Ok(())
}

#[test]
fn cleanup_subscription_missing_source_and_version_overflow_abort_without_committed_changes()
-> TestResult {
    use super::{RosterQuota, RosterSubscription, SubscriptionState};
    let storage = storage()?;
    let owner = key("alice@example.com")?;
    let contact = jid("bob@example.com")?;
    block_on(write(&storage, async |tx| {
        tx.create_account(new_account(owner.as_str(), 10)?).await?;
        Ok::<_, Box<dyn Error>>(())
    }))?;
    block_on(async {
        let mut tx = storage.begin_write().await?;
        let before = storage.begin_read().await?;
        tx.put_roster_item(
            &owner,
            &item(contact.as_str(), None, &[])?,
            RosterQuota::default(),
        )
        .await?;
        assert!(matches!(
            tx.set_roster_subscription(
                &before,
                &owner,
                &contact,
                RosterSubscription {
                    state: SubscriptionState::From,
                    ..Default::default()
                }
            )
            .await,
            Err(super::RosterError::Storage(_))
        ));
        assert_eq!(tx.roster_version(&owner).await?.get(), 1);
        Ok::<_, Box<dyn Error>>(())
    })?;
    assert!(stored_item(&storage, ITEM_KEY)?.is_none());
    insert_item(&storage, ITEM_KEY, &[0, 0, 255, 255, 255, 255, 0, 0, 0, 0])?;
    let transaction = storage.as_ref().begin_write()?;
    transaction
        .open_table(super::redb::VERSIONS)?
        .insert(owner.as_str(), u64::MAX)?;
    transaction.commit()?;
    let original = stored_item(&storage, ITEM_KEY)?;
    block_on(async {
        let mut tx = storage.begin_write().await?;
        let before = storage.begin_read().await?;
        assert!(matches!(
            tx.set_roster_subscription(
                &before,
                &owner,
                &contact,
                RosterSubscription {
                    state: SubscriptionState::From,
                    ..Default::default()
                }
            )
            .await,
            Err(super::RosterError::ValueTooLarge)
        ));
        Ok::<_, Box<dyn Error>>(())
    })?;
    assert_eq!(stored_item(&storage, ITEM_KEY)?, original);
    assert_eq!(
        block_on(async { storage.begin_read().await?.roster_version(&owner).await })?.get(),
        u64::MAX
    );
    Ok(())
}

#[test]
fn non_growing_metadata_replacement_cannot_bypass_group_cap_and_legacy_rows_can_recover()
-> TestResult {
    let storage = storage()?;
    let owner = key("alice@example.com")?;
    let contact = jid("bob@example.com")?;
    block_on(async {
        let mut tx = storage.begin_write().await?;
        tx.create_account(new_account(owner.as_str(), 10)?).await?;
        let original = item(contact.as_str(), Some(&"x".repeat(100)), &[])?;
        tx.put_roster_item(&owner, &original, quota(2, 1024))
            .await?;
        let replacement = item(contact.as_str(), None, &["a"; 9])?;
        assert!(matches!(
            tx.put_roster_item(&owner, &replacement, quota(2, 1024))
                .await,
            Err(super::RosterError::QuotaExceeded)
        ));
        assert_eq!(tx.roster_version(&owner).await?.get(), 1);
        assert_eq!(
            tx.roster_item(&owner, &contact, quota(2, 1024))
                .await?
                .ok_or("missing")?,
            original
        );
        tx.commit().await?;
        Ok::<_, Box<dyn Error>>(())
    })?;
    let mut legacy = vec![0, 0, 255, 255, 255, 255, 9, 0, 0, 0];
    legacy.extend_from_slice(&[0; 9 * 4]);
    insert_item(&storage, ITEM_KEY, &legacy)?;
    block_on(async {
        let mut tx = storage.begin_write().await?;
        assert!(matches!(
            tx.roster(&owner, quota(2, 1024)).await,
            Err(super::RosterError::QuotaExceeded)
        ));
        tx.put_roster_item(
            &owner,
            &item(contact.as_str(), None, &[""; 8])?,
            quota(1, 1),
        )
        .await?;
        assert_eq!(
            tx.roster(&owner, quota(1, 1024)).await?.items[0]
                .groups
                .len(),
            8
        );
        tx.commit().await?;
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn repeated_legacy_header_transitions_preserve_metadata_and_use_current_version() -> TestResult {
    use super::{RosterSubscription, SubscriptionState};
    let storage = storage()?;
    let owner = key("alice@example.com")?;
    let contact = jid("bob@example.com")?;
    block_on(write(&storage, async |tx| {
        tx.create_account(new_account(owner.as_str(), 10)?).await?;
        Ok::<_, Box<dyn Error>>(())
    }))?;
    for groups in [false, true] {
        let mut raw = vec![3, 0];
        if groups {
            raw.extend_from_slice(&u32::MAX.to_le_bytes());
            raw.extend_from_slice(&9u32.to_le_bytes());
            for _ in 0..9 {
                raw.extend_from_slice(&0u32.to_le_bytes());
            }
        } else {
            raw.extend_from_slice(&8192u32.to_le_bytes());
            raw.extend_from_slice(&[b'x'; 8192]);
            raw.extend_from_slice(&0u32.to_le_bytes());
        }
        insert_item(&storage, ITEM_KEY, &raw)?;
        block_on(async {
            let mut tx = storage.begin_write().await?;
            let start = tx.roster_version(&owner).await?.get();
            let mut expected = RosterSubscription {
                state: SubscriptionState::Both,
                ..Default::default()
            };
            for (offset, state) in [SubscriptionState::From, SubscriptionState::None]
                .into_iter()
                .enumerate()
            {
                let next = RosterSubscription {
                    state,
                    ..Default::default()
                };
                assert_eq!(
                    tx.transition_roster_subscription(&owner, &contact, expected, next)
                        .await?
                        .ok_or("missing change")?
                        .get(),
                    start + offset as u64 + 1
                );
                expected = next;
            }
            assert_eq!(
                tx.transition_roster_subscription(&owner, &contact, expected, expected)
                    .await?,
                None
            );
            assert!(matches!(
                tx.transition_roster_subscription(
                    &owner,
                    &contact,
                    RosterSubscription {
                        state: SubscriptionState::Both,
                        ..Default::default()
                    },
                    expected
                )
                .await,
                Err(super::RosterError::Storage(_))
            ));
            tx.commit().await?;
            Ok::<_, Box<dyn Error>>(())
        })?;
        let updated = stored_item(&storage, ITEM_KEY)?.ok_or("missing")?;
        assert_eq!(&updated[2..], &raw[2..]);
        assert_eq!(&updated[..2], &[0, 0]);
    }
    Ok(())
}

#[test]
fn default_roster_byte_quota_admits_two_mib_and_rejects_further_growth() -> TestResult {
    let storage = storage()?;
    let owner = key("alice@example.com")?;
    let limit = RosterQuota::default();
    assert_eq!(limit.max_bytes.get(), 2_097_152);
    block_on(async {
        let mut tx = storage.begin_write().await?;
        tx.create_account(new_account(owner.as_str(), 10)?).await?;
        let mut contact = item("bob@example.com", None, &[])?;
        let overhead = owner.as_str().len() + 1 + contact.jid.as_str().len() + 10;
        let name_len = limit.max_bytes.get() - overhead;
        contact.name = Some("x".repeat(name_len + 1).into_boxed_str());
        assert!(matches!(
            tx.put_roster_item(&owner, &contact, limit).await,
            Err(super::RosterError::QuotaExceeded)
        ));
        assert_eq!(tx.roster_version(&owner).await?.get(), 0);
        let mut name = contact.name.take().ok_or("missing name")?.into_string();
        name.truncate(name_len);
        contact.name = Some(name.into_boxed_str());
        assert_eq!(tx.put_roster_item(&owner, &contact, limit).await?.get(), 1);
        assert!(matches!(
            tx.put_roster_item(&owner, &item("carol@example.com", None, &[])?, limit)
                .await,
            Err(super::RosterError::QuotaExceeded)
        ));
        assert_eq!(tx.roster_version(&owner).await?.get(), 1);
        tx.commit().await?;
        Ok::<_, Box<dyn Error>>(())
    })
}
