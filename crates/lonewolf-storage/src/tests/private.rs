// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroUsize;

use futures_executor::block_on;

use super::{TestResult, key, new_account};
use crate::account::{AccountKey, AccountWrites};
use crate::private::{
    PrivateXmlChange, PrivateXmlError, PrivateXmlQuota, PrivateXmlReads, PrivateXmlWrites,
};
use crate::{Storage, WriteTransaction};

const PREFS: &str =
    "<prefs xmlns='urn:test:prefs' xml:lang='' xml:space='default'><nick>Ålice</nick></prefs>";
const BOOKMARKS: &str = "<storage xmlns='storage:bookmarks' xml:lang='' xml:space='default'><conference jid='room@example.com'/></storage>";

fn put<'a>(namespace: &'a str, name: &'a str, xml: &'a str) -> PrivateXmlChange<'a> {
    PrivateXmlChange {
        namespace,
        name,
        xml: Some(xml),
    }
}

fn remove<'a>(namespace: &'a str, name: &'a str) -> PrivateXmlChange<'a> {
    PrivateXmlChange {
        namespace,
        name,
        xml: None,
    }
}

fn quota(items: usize, bytes: usize) -> TestResult<PrivateXmlQuota> {
    Ok(PrivateXmlQuota {
        max_items: NonZeroUsize::new(items).ok_or("zero items")?,
        max_bytes: NonZeroUsize::new(bytes).ok_or("zero bytes")?,
    })
}

async fn stored<T: PrivateXmlReads>(
    transaction: &T,
    owner: &AccountKey,
    namespace: &str,
    name: &str,
) -> TestResult<Option<String>> {
    Ok(transaction
        .private_xml(owner, namespace, name)
        .await?
        .map(|stored| stored.xml.into()))
}

pub(crate) fn private_xml_round_trip_isolates_owners_namespaces_and_names<S: Storage>(
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
            writer.create_account(new_account(name, 10)?).await?;
            writer
                .update_private_xml(
                    &key(name)?,
                    &[put("urn:test:prefs", "prefs", PREFS)],
                    PrivateXmlQuota::default(),
                )
                .await?;
        }
        let alice = key(names[0])?;
        writer
            .update_private_xml(
                &alice,
                &[
                    put("storage:bookmarks", "storage", BOOKMARKS),
                    put("urn:test:prefs", "other", "<other xmlns='urn:test:prefs'/>"),
                ],
                PrivateXmlQuota::default(),
            )
            .await?;
        writer.commit().await?;
        let reader = storage.begin_read().await?;
        for name in names {
            assert_eq!(
                stored(&reader, &key(name)?, "urn:test:prefs", "prefs")
                    .await?
                    .as_deref(),
                Some(PREFS)
            );
        }
        assert_eq!(
            stored(&reader, &alice, "storage:bookmarks", "storage")
                .await?
                .as_deref(),
            Some(BOOKMARKS)
        );
        assert_eq!(
            stored(&reader, &alice, "urn:test:prefs", "other")
                .await?
                .as_deref(),
            Some("<other xmlns='urn:test:prefs'/>")
        );
        for (namespace, name) in [
            ("urn:test:prefs", "Prefs"),
            ("urn:test:Prefs", "prefs"),
            ("storage:bookmarks", "prefs"),
            ("", "prefs"),
        ] {
            assert!(stored(&reader, &alice, namespace, name).await?.is_none());
        }
        for name in &names[1..] {
            assert!(
                stored(&reader, &key(name)?, "storage:bookmarks", "storage")
                    .await?
                    .is_none()
            );
        }
        Ok(())
    })
}

pub(crate) fn private_xml_updates_apply_in_order_and_the_last_change_wins<S: Storage>(
    storage: S,
) -> TestResult {
    block_on(async {
        let owner = key("alice@example.com")?;
        let mut writer = storage.begin_write().await?;
        writer
            .create_account(new_account("alice@example.com", 10)?)
            .await?;
        writer
            .update_private_xml(
                &owner,
                &[
                    put("urn:a", "a", "<a xmlns='urn:a'>1</a>"),
                    put("urn:a", "a", "<a xmlns='urn:a'>2</a>"),
                    put("urn:b", "b", "<b xmlns='urn:b'>1</b>"),
                    remove("urn:b", "b"),
                    remove("urn:c", "c"),
                ],
                PrivateXmlQuota::default(),
            )
            .await?;
        assert_eq!(
            stored(&writer, &owner, "urn:a", "a").await?.as_deref(),
            Some("<a xmlns='urn:a'>2</a>")
        );
        assert!(stored(&writer, &owner, "urn:b", "b").await?.is_none());
        writer
            .update_private_xml(
                &owner,
                &[
                    remove("urn:a", "a"),
                    put("urn:a", "a", "<a xmlns='urn:a'>3</a>"),
                ],
                PrivateXmlQuota::default(),
            )
            .await?;
        writer.commit().await?;
        assert_eq!(
            stored(&storage.begin_read().await?, &owner, "urn:a", "a")
                .await?
                .as_deref(),
            Some("<a xmlns='urn:a'>3</a>")
        );
        Ok(())
    })
}

pub(crate) fn private_xml_quota_counts_items_and_bytes_and_rejections_change_nothing<S: Storage>(
    storage: S,
) -> TestResult {
    block_on(async {
        let owner = key("alice@example.com")?;
        let limits = quota(2, 10)?;
        let mut writer = storage.begin_write().await?;
        writer
            .create_account(new_account("alice@example.com", 10)?)
            .await?;
        writer
            .update_private_xml(
                &owner,
                &[put("urn:a", "a", "aaaa"), put("urn:b", "b", "bbbbbb")],
                limits,
            )
            .await?;
        for changes in [
            vec![put("urn:c", "c", "c")],
            vec![put("urn:a", "a", "aaaaa")],
            vec![put("urn:a", "a", "a"), put("urn:c", "c", "c")],
            vec![remove("urn:a", "a"), put("urn:c", "c", "ccccc")],
            vec![put("urn:a", "a", "aaaaaaaaaaa")],
        ] {
            assert!(matches!(
                writer.update_private_xml(&owner, &changes, limits).await,
                Err(PrivateXmlError::QuotaExceeded)
            ));
            assert_eq!(
                stored(&writer, &owner, "urn:a", "a").await?.as_deref(),
                Some("aaaa")
            );
            assert_eq!(
                stored(&writer, &owner, "urn:b", "b").await?.as_deref(),
                Some("bbbbbb")
            );
            assert!(stored(&writer, &owner, "urn:c", "c").await?.is_none());
        }
        writer
            .update_private_xml(
                &owner,
                &[remove("urn:a", "a"), put("urn:c", "c", "cccc")],
                limits,
            )
            .await?;
        writer.commit().await?;
        let reader = storage.begin_read().await?;
        assert!(stored(&reader, &owner, "urn:a", "a").await?.is_none());
        assert_eq!(
            stored(&reader, &owner, "urn:c", "c").await?.as_deref(),
            Some("cccc")
        );
        Ok(())
    })
}

pub(crate) fn private_xml_over_quota_accounts_can_shrink_but_not_grow<S: Storage>(
    storage: S,
) -> TestResult {
    block_on(async {
        let owner = key("alice@example.com")?;
        let mut writer = storage.begin_write().await?;
        writer
            .create_account(new_account("alice@example.com", 10)?)
            .await?;
        writer
            .update_private_xml(
                &owner,
                &[
                    put("urn:a", "a", "aaaa"),
                    put("urn:b", "b", "bbbb"),
                    put("urn:c", "c", "cccc"),
                ],
                PrivateXmlQuota::default(),
            )
            .await?;
        let reduced = quota(1, 4)?;
        for changes in [
            vec![put("urn:d", "d", "d")],
            vec![put("urn:a", "a", "aaaaa")],
        ] {
            assert!(matches!(
                writer.update_private_xml(&owner, &changes, reduced).await,
                Err(PrivateXmlError::QuotaExceeded)
            ));
        }
        writer
            .update_private_xml(&owner, &[put("urn:a", "a", "a")], reduced)
            .await?;
        writer
            .update_private_xml(&owner, &[remove("urn:b", "b")], reduced)
            .await?;
        writer
            .update_private_xml(
                &owner,
                &[remove("urn:c", "c"), put("urn:d", "d", "dd")],
                reduced,
            )
            .await?;
        writer.commit().await?;
        let reader = storage.begin_read().await?;
        assert_eq!(
            stored(&reader, &owner, "urn:a", "a").await?.as_deref(),
            Some("a")
        );
        assert!(stored(&reader, &owner, "urn:b", "b").await?.is_none());
        assert!(stored(&reader, &owner, "urn:c", "c").await?.is_none());
        assert_eq!(
            stored(&reader, &owner, "urn:d", "d").await?.as_deref(),
            Some("dd")
        );
        Ok(())
    })
}

pub(crate) fn private_xml_large_elements_remain_readable_and_replaceable_after_quota_reduction<
    S: Storage,
>(
    storage: S,
) -> TestResult {
    block_on(async {
        let owner = key("alice@example.com")?;
        let large = "x".repeat(1_048_577);
        let same = "y".repeat(large.len());
        let smaller = "z".repeat(large.len() - 1);
        let mut writer = storage.begin_write().await?;
        writer
            .create_account(new_account("alice@example.com", 10)?)
            .await?;
        writer
            .update_private_xml(
                &owner,
                &[put("urn:a", "a", &large)],
                PrivateXmlQuota::default(),
            )
            .await?;
        assert_eq!(
            stored(&writer, &owner, "urn:a", "a").await?.as_deref(),
            Some(large.as_str())
        );
        writer.commit().await?;
        assert_eq!(
            stored(&storage.begin_read().await?, &owner, "urn:a", "a")
                .await?
                .as_deref(),
            Some(large.as_str())
        );

        let reduced = quota(1, 16)?;
        let mut writer = storage.begin_write().await?;
        for xml in [&same, &smaller] {
            writer
                .update_private_xml(&owner, &[put("urn:a", "a", xml)], reduced)
                .await?;
        }
        assert!(matches!(
            writer
                .update_private_xml(&owner, &[put("urn:a", "a", &large)], reduced)
                .await,
            Err(PrivateXmlError::QuotaExceeded)
        ));
        assert_eq!(
            stored(&writer, &owner, "urn:a", "a").await?.as_deref(),
            Some(smaller.as_str())
        );
        writer.commit().await?;
        assert_eq!(
            stored(&storage.begin_read().await?, &owner, "urn:a", "a")
                .await?
                .as_deref(),
            Some(smaller.as_str())
        );

        let mut writer = storage.begin_write().await?;
        writer
            .update_private_xml(
                &owner,
                &[put("urn:a", "a", &large), put("urn:a", "a", "ok")],
                reduced,
            )
            .await?;
        writer.commit().await?;
        assert_eq!(
            stored(&storage.begin_read().await?, &owner, "urn:a", "a")
                .await?
                .as_deref(),
            Some("ok")
        );
        Ok(())
    })
}

pub(crate) fn private_xml_missing_accounts_reject_updates_and_allow_repeated_clearing<
    S: Storage,
>(
    storage: S,
) -> TestResult {
    block_on(async {
        let owner = key("alice@example.com")?;
        let mut writer = storage.begin_write().await?;
        assert!(matches!(
            writer
                .update_private_xml(
                    &owner,
                    &[put("urn:a", "a", "a")],
                    PrivateXmlQuota::default()
                )
                .await,
            Err(PrivateXmlError::NoAccount)
        ));
        writer.clear_private_xml(&owner).await?;
        writer.clear_private_xml(&owner).await?;
        writer
            .create_account(new_account("alice@example.com", 10)?)
            .await?;
        writer
            .update_private_xml(
                &owner,
                &[put("urn:a", "a", "a")],
                PrivateXmlQuota::default(),
            )
            .await?;
        writer.delete_account(&owner).await?;
        assert!(matches!(
            writer
                .update_private_xml(
                    &owner,
                    &[put("urn:b", "b", "b")],
                    PrivateXmlQuota::default()
                )
                .await,
            Err(PrivateXmlError::NoAccount)
        ));
        writer.clear_private_xml(&owner).await?;
        writer.clear_private_xml(&owner).await?;
        assert!(stored(&writer, &owner, "urn:a", "a").await?.is_none());
        writer.commit().await?;
        Ok(())
    })
}

pub(crate) fn private_xml_clear_removes_only_one_owner<S: Storage>(storage: S) -> TestResult {
    block_on(async {
        let names = [
            "alice@example.com",
            "alice@example.co",
            "alice@example.comm",
            "alic@example.com",
            "bob@example.com",
        ];
        let mut writer = storage.begin_write().await?;
        for name in names {
            writer.create_account(new_account(name, 10)?).await?;
            writer
                .update_private_xml(
                    &key(name)?,
                    &[put("urn:a", "a", "a"), put("urn:b", "b", "b")],
                    PrivateXmlQuota::default(),
                )
                .await?;
        }
        writer.clear_private_xml(&key(names[0])?).await?;
        writer.commit().await?;
        let reader = storage.begin_read().await?;
        for name in names {
            let present = name != names[0];
            for (namespace, element) in [("urn:a", "a"), ("urn:b", "b")] {
                assert_eq!(
                    stored(&reader, &key(name)?, namespace, element)
                        .await?
                        .is_some(),
                    present,
                    "{name}"
                );
            }
        }
        Ok(())
    })
}

pub(crate) fn private_xml_snapshots_ignore_uncommitted_and_dropped_updates<S: Storage>(
    storage: S,
) -> TestResult {
    block_on(async {
        let owner = key("alice@example.com")?;
        let mut writer = storage.begin_write().await?;
        writer
            .create_account(new_account("alice@example.com", 10)?)
            .await?;
        writer
            .update_private_xml(
                &owner,
                &[put("urn:a", "a", "old")],
                PrivateXmlQuota::default(),
            )
            .await?;
        writer.commit().await?;
        let old = storage.begin_read().await?;
        for clear in [false, true] {
            let mut writer = storage.begin_write().await?;
            if clear {
                writer.clear_private_xml(&owner).await?;
            } else {
                writer
                    .update_private_xml(
                        &owner,
                        &[put("urn:a", "a", "new")],
                        PrivateXmlQuota::default(),
                    )
                    .await?;
            }
            assert_eq!(
                stored(&storage.begin_read().await?, &owner, "urn:a", "a")
                    .await?
                    .as_deref(),
                Some("old")
            );
            drop(writer);
        }
        let mut writer = storage.begin_write().await?;
        writer
            .update_private_xml(
                &owner,
                &[put("urn:a", "a", "new")],
                PrivateXmlQuota::default(),
            )
            .await?;
        writer.commit().await?;
        assert_eq!(
            stored(&old, &owner, "urn:a", "a").await?.as_deref(),
            Some("old")
        );
        assert_eq!(
            stored(&storage.begin_read().await?, &owner, "urn:a", "a")
                .await?
                .as_deref(),
            Some("new")
        );
        Ok(())
    })
}
