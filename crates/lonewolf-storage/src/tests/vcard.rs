// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroUsize;

use futures_executor::block_on;

use super::{TestResult, key, new_account, poll};
use crate::account::{AccountReads, AccountWrites};
use crate::vcard::{MAX_VCARD_BYTES, VCardError, VCardQuota, VCardReads, VCardWrites};
use crate::{Storage, WriteTransaction};

const OLD: &str = "<vCard xmlns='vcard-temp'><FN>Private Ålice</FN><NOTE>old</NOTE></vCard>";
const NEW: &str = "<vCard xmlns='vcard-temp'><FN>New</FN></vCard>";

pub(crate) fn vcard_round_trip_replaces_the_whole_document_and_isolates_owners<S: Storage>(
    storage: S,
) -> TestResult {
    block_on(async {
        let names = [
            "alice@example.com",
            "alice2@example.com",
            "alice@example.org",
        ];
        let mut writer = storage.begin_write().await?;
        for name in names {
            let owner = key(name)?;
            assert!(writer.vcard(&owner).await?.is_none());
            writer.create_account(new_account(name, 10)?).await?;
            assert!(writer.vcard(&owner).await?.is_none());
            writer
                .replace_vcard(&owner, OLD, VCardQuota::default())
                .await?;
        }
        let alice = key(names[0])?;
        writer
            .replace_vcard(&alice, NEW, VCardQuota::default())
            .await?;
        assert_eq!(
            writer
                .vcard(&alice)
                .await?
                .ok_or("missing vCard")?
                .xml
                .as_ref(),
            NEW
        );
        writer.commit().await?;
        let reader = storage.begin_read().await?;
        for name in &names[1..] {
            assert_eq!(
                reader
                    .vcard(&key(name)?)
                    .await?
                    .ok_or("missing vCard")?
                    .xml
                    .as_ref(),
                OLD
            );
        }
        assert_eq!(
            reader
                .vcard(&alice)
                .await?
                .ok_or("missing vCard")?
                .xml
                .as_ref(),
            NEW
        );
        let mut writer = storage.begin_write().await?;
        writer.delete_vcard(&alice).await?;
        writer.commit().await?;
        let reader = storage.begin_read().await?;
        assert!(reader.vcard(&alice).await?.is_none());
        for name in &names[1..] {
            assert_eq!(
                reader
                    .vcard(&key(name)?)
                    .await?
                    .ok_or("missing vCard")?
                    .xml
                    .as_ref(),
                OLD
            );
        }
        Ok(())
    })
}

pub(crate) fn vcard_snapshots_uncommitted_changes_and_drops_are_atomic<S: Storage>(
    storage: S,
) -> TestResult {
    block_on(async {
        let owner = key("alice@example.com")?;
        let absent = storage.begin_read().await?;
        let mut writer = storage.begin_write().await?;
        writer
            .create_account(new_account("alice@example.com", 10)?)
            .await?;
        writer
            .replace_vcard(&owner, OLD, VCardQuota::default())
            .await?;
        assert!(storage.begin_read().await?.vcard(&owner).await?.is_none());
        assert_eq!(
            writer
                .vcard(&owner)
                .await?
                .ok_or("missing vCard")?
                .xml
                .as_ref(),
            OLD
        );
        drop(writer);
        let reader = storage.begin_read().await?;
        assert!(reader.account(&owner).await?.is_none());
        assert!(reader.vcard(&owner).await?.is_none());
        let mut writer = storage.begin_write().await?;
        writer
            .create_account(new_account("alice@example.com", 10)?)
            .await?;
        writer
            .replace_vcard(&owner, OLD, VCardQuota::default())
            .await?;
        writer.commit().await?;
        assert!(absent.vcard(&owner).await?.is_none());
        assert!(absent.account(&owner).await?.is_none());
        let old = storage.begin_read().await?;
        assert!(old.account(&owner).await?.is_some());
        for delete in [false, true] {
            let mut writer = storage.begin_write().await?;
            if delete {
                writer.delete_vcard(&owner).await?;
                assert!(writer.vcard(&owner).await?.is_none());
            } else {
                writer
                    .replace_vcard(&owner, NEW, VCardQuota::default())
                    .await?;
            }
            drop(writer);
            assert_eq!(
                storage
                    .begin_read()
                    .await?
                    .vcard(&owner)
                    .await?
                    .ok_or("missing vCard")?
                    .xml
                    .as_ref(),
                OLD
            );
        }
        let mut writer = storage.begin_write().await?;
        writer
            .replace_vcard(&owner, NEW, VCardQuota::default())
            .await?;
        assert_eq!(
            storage
                .begin_read()
                .await?
                .vcard(&owner)
                .await?
                .ok_or("missing vCard")?
                .xml
                .as_ref(),
            OLD
        );
        writer.commit().await?;
        assert_eq!(
            old.vcard(&owner)
                .await?
                .ok_or("missing vCard")?
                .xml
                .as_ref(),
            OLD
        );
        assert_eq!(
            storage
                .begin_read()
                .await?
                .vcard(&owner)
                .await?
                .ok_or("missing vCard")?
                .xml
                .as_ref(),
            NEW
        );
        Ok(())
    })
}

pub(crate) fn vcard_quotas_count_bytes_and_rejections_preserve_committable_state<S: Storage>(
    storage: S,
) -> TestResult {
    block_on(async {
        let owner = key("alice@example.com")?;
        let quota = VCardQuota {
            max_bytes: NonZeroUsize::new(4).ok_or("invalid quota")?,
        };
        let mut writer = storage.begin_write().await?;
        writer
            .create_account(new_account("alice@example.com", 10)?)
            .await?;
        writer.replace_vcard(&owner, "éé", quota).await?;
        for xml in ["12345", "ééé"] {
            assert!(matches!(
                writer.replace_vcard(&owner, xml, quota).await,
                Err(VCardError::QuotaExceeded)
            ));
        }
        assert!(matches!(
            writer
                .replace_vcard(
                    &owner,
                    "éé",
                    VCardQuota {
                        max_bytes: NonZeroUsize::MIN
                    }
                )
                .await,
            Err(VCardError::QuotaExceeded)
        ));
        writer
            .create_account(new_account("bob@example.com", 20)?)
            .await?;
        writer.commit().await?;
        let reader = storage.begin_read().await?;
        assert!(reader.account(&key("bob@example.com")?).await?.is_some());
        assert_eq!(
            reader
                .vcard(&owner)
                .await?
                .ok_or("missing vCard")?
                .xml
                .as_ref(),
            "éé"
        );
        let mut writer = storage.begin_write().await?;
        writer
            .replace_vcard(
                &owner,
                "x",
                VCardQuota {
                    max_bytes: NonZeroUsize::MIN,
                },
            )
            .await?;
        writer.commit().await?;
        assert_eq!(
            storage
                .begin_read()
                .await?
                .vcard(&owner)
                .await?
                .ok_or("missing vCard")?
                .xml
                .as_ref(),
            "x"
        );
        Ok(())
    })
}

pub(crate) fn vcard_hard_ceiling_applies_even_with_an_oversized_quota<S: Storage>(
    storage: S,
) -> TestResult {
    block_on(async {
        let owner = key("alice@example.com")?;
        let quota = VCardQuota {
            max_bytes: NonZeroUsize::MAX,
        };
        let mut writer = storage.begin_write().await?;
        writer
            .create_account(new_account("alice@example.com", 10)?)
            .await?;
        let exact = "é".repeat(MAX_VCARD_BYTES / 2);
        writer.replace_vcard(&owner, &exact, quota).await?;
        let oversized = "x".repeat(MAX_VCARD_BYTES + 1);
        assert!(matches!(
            writer.replace_vcard(&owner, &oversized, quota).await,
            Err(VCardError::QuotaExceeded)
        ));
        writer.commit().await?;
        assert_eq!(
            storage
                .begin_read()
                .await?
                .vcard(&owner)
                .await?
                .ok_or("missing vCard")?
                .xml
                .as_ref(),
            exact
        );
        let mut writer = storage.begin_write().await?;
        writer
            .replace_vcard(&owner, "", VCardQuota::default())
            .await?;
        writer.commit().await?;
        assert_eq!(
            storage
                .begin_read()
                .await?
                .vcard(&owner)
                .await?
                .ok_or("missing empty vCard")?
                .xml
                .as_ref(),
            ""
        );
        Ok(())
    })
}

pub(crate) fn vcard_missing_accounts_reject_replacement_and_allow_repeated_removal<S: Storage>(
    storage: S,
) -> TestResult {
    block_on(async {
        let owner = key("alice@example.com")?;
        let mut writer = storage.begin_write().await?;
        assert!(matches!(
            writer
                .replace_vcard(&owner, OLD, VCardQuota::default())
                .await,
            Err(VCardError::NoAccount)
        ));
        assert!(writer.vcard(&owner).await?.is_none());
        writer.delete_vcard(&owner).await?;
        writer
            .create_account(new_account("alice@example.com", 10)?)
            .await?;
        writer.delete_account(&owner).await?;
        assert!(matches!(
            writer
                .replace_vcard(&owner, OLD, VCardQuota::default())
                .await,
            Err(VCardError::NoAccount)
        ));
        assert!(writer.vcard(&owner).await?.is_none());
        writer.delete_vcard(&owner).await?;
        writer.commit().await?;
        assert!(storage.begin_read().await?.vcard(&owner).await?.is_none());
        let mut writer = storage.begin_write().await?;
        writer
            .create_account(new_account("alice@example.com", 10)?)
            .await?;
        writer
            .replace_vcard(&owner, OLD, VCardQuota::default())
            .await?;
        writer.commit().await?;
        let mut writer = storage.begin_write().await?;
        writer.delete_account(&owner).await?;
        assert!(matches!(
            writer
                .replace_vcard(&owner, NEW, VCardQuota::default())
                .await,
            Err(VCardError::NoAccount)
        ));
        assert_eq!(
            writer
                .vcard(&owner)
                .await?
                .ok_or("missing vCard")?
                .xml
                .as_ref(),
            OLD
        );
        writer.delete_vcard(&owner).await?;
        writer.delete_vcard(&owner).await?;
        writer.commit().await?;
        let reader = storage.begin_read().await?;
        assert!(reader.account(&owner).await?.is_none());
        assert!(reader.vcard(&owner).await?.is_none());
        Ok(())
    })
}

pub(crate) fn vcard_concurrent_writers_observe_only_complete_documents<S: Storage>(
    storage: S,
) -> TestResult {
    block_on(async {
        let owner = key("alice@example.com")?;
        let mut first = storage.begin_write().await?;
        first
            .create_account(new_account("alice@example.com", 10)?)
            .await?;
        first
            .replace_vcard(&owner, OLD, VCardQuota::default())
            .await?;
        let mut second = Box::pin(storage.begin_write());
        assert!(poll(second.as_mut()).is_pending());
        assert!(storage.begin_read().await?.vcard(&owner).await?.is_none());
        first.commit().await?;
        let mut second = second.await?;
        assert_eq!(
            second
                .vcard(&owner)
                .await?
                .ok_or("missing vCard")?
                .xml
                .as_ref(),
            OLD
        );
        second
            .replace_vcard(&owner, NEW, VCardQuota::default())
            .await?;
        let old = storage.begin_read().await?;
        assert_eq!(
            old.vcard(&owner)
                .await?
                .ok_or("missing vCard")?
                .xml
                .as_ref(),
            OLD
        );
        second.commit().await?;
        assert_eq!(
            old.vcard(&owner)
                .await?
                .ok_or("missing vCard")?
                .xml
                .as_ref(),
            OLD
        );
        assert_eq!(
            storage
                .begin_read()
                .await?
                .vcard(&owner)
                .await?
                .ok_or("missing vCard")?
                .xml
                .as_ref(),
            NEW
        );
        Ok(())
    })
}
