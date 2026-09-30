// SPDX-License-Identifier: Apache-2.0

use futures_executor::block_on;

use super::{TestResult, item, item_with_subscription, jid, key, pending, read, write};
use crate::roster::{
    RosterReads, RosterSubscription, RosterVersion, RosterWrites, SubscriptionState,
};
use crate::{Storage, WriteTransaction};

pub(crate) fn new_roster_is_empty_at_version_zero<S: Storage>(storage: S) -> TestResult {
    let alice = key("alice@example.com")?;
    block_on(async {
        let snapshot = read(&storage, async |tx| tx.roster(&alice).await).await?;
        assert_eq!(snapshot.version, RosterVersion::default());
        assert!(snapshot.items.is_empty());
        Ok(())
    })
}

pub(crate) fn put_roster_item_stores_every_field_and_advances_the_version<S: Storage>(
    storage: S,
) -> TestResult {
    let owner = key("alice@example.com")?;
    let contact = jid("BOB@EXAMPLE.COM")?;
    let subscription = RosterSubscription {
        state: SubscriptionState::From,
        pending_out: true,
        approved: true,
    };
    let stored = item_with_subscription(
        "BOB@EXAMPLE.COM",
        Some("Bob"),
        &["Friends", "Work"],
        subscription,
    )?;
    block_on(async {
        let version = write(&storage, async |tx| {
            tx.put_roster_item(&owner, &stored).await
        })
        .await?;
        assert_eq!(version.get(), 1);

        let reader = storage.begin_read().await?;
        let read_back = reader
            .roster_item(&owner, &contact)
            .await?
            .ok_or("missing item")?;
        assert_eq!(read_back.jid, contact);
        assert_eq!(read_back.name.as_deref(), Some("Bob"));
        assert_eq!(
            [read_back.groups[0].as_ref(), read_back.groups[1].as_ref()],
            ["Friends", "Work"]
        );
        assert_eq!(read_back.subscription, subscription);
        assert_eq!(read_back, stored);
        let snapshot = reader.roster(&owner).await?;
        assert_eq!(snapshot.version, version);
        assert_eq!(snapshot.items, [stored]);
        Ok(())
    })
}

pub(crate) fn put_roster_item_replaces_the_item_for_the_same_jid_and_advances_again<S: Storage>(
    storage: S,
) -> TestResult {
    let owner = key("alice@example.com")?;
    let contact = jid("bob@example.com")?;
    let original = item_with_subscription(
        "bob@example.com",
        Some("Bob"),
        &["Friends"],
        RosterSubscription {
            state: SubscriptionState::To,
            pending_out: true,
            approved: false,
        },
    )?;
    let replacement = item_with_subscription(
        "bob@example.com",
        Some("Robert"),
        &["Work", "Family"],
        RosterSubscription {
            state: SubscriptionState::Both,
            pending_out: false,
            approved: true,
        },
    )?;
    block_on(async {
        write(&storage, async |tx| {
            tx.put_roster_item(&owner, &original).await
        })
        .await?;
        let version = write(&storage, async |tx| {
            tx.put_roster_item(&owner, &replacement).await
        })
        .await?;
        assert_eq!(version.get(), 2);

        let reader = storage.begin_read().await?;
        let snapshot = reader.roster(&owner).await?;
        assert_eq!(snapshot.version, version);
        assert_eq!(snapshot.items.len(), 1);
        assert_eq!(snapshot.items[0].name.as_deref(), Some("Robert"));
        assert_eq!(snapshot.items[0].groups.len(), 2);
        assert_eq!(snapshot.items[0].subscription, replacement.subscription);
        assert_eq!(
            reader.roster_item(&owner, &contact).await?,
            Some(replacement)
        );
        Ok(())
    })
}

pub(crate) fn rosters_are_isolated_by_owner_and_sorted_by_contact<S: Storage>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let carol = key("carol@example.com")?;
    let bob = jid("bob@example.com")?;
    block_on(async {
        let mut writer = storage.begin_write().await?;
        for contact in ["zara@example.com", "bob@example.com"] {
            writer
                .put_roster_item(&alice, &item(contact, None, &[])?)
                .await?;
        }
        writer
            .put_roster_item(&carol, &item("dave@example.com", None, &[])?)
            .await?;
        writer.commit().await?;

        let reader = storage.begin_read().await?;
        let snapshot = reader.roster(&alice).await?;
        assert_eq!(snapshot.version.get(), 2);
        assert_eq!(snapshot.items.len(), 2);
        assert_eq!(snapshot.items[0].jid.as_str(), "bob@example.com");
        assert_eq!(snapshot.items[1].jid.as_str(), "zara@example.com");
        let snapshot = reader.roster(&carol).await?;
        assert_eq!(snapshot.version.get(), 1);
        assert_eq!(snapshot.items.len(), 1);
        assert_eq!(snapshot.items[0].jid.as_str(), "dave@example.com");
        assert!(reader.roster_item(&carol, &bob).await?.is_none());
        Ok(())
    })
}

pub(crate) fn roster_item_returns_exactly_the_stored_item_or_none<S: Storage>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let carol = key("carol@example.com")?;
    let bob = jid("bob@example.com")?;
    let dave = jid("dave@example.com")?;
    let stored = item_with_subscription(
        "bob@example.com",
        Some("Bob"),
        &["Friends"],
        RosterSubscription {
            state: SubscriptionState::To,
            ..RosterSubscription::default()
        },
    )?;
    block_on(async {
        write(&storage, async |tx| {
            tx.put_roster_item(&alice, &stored).await
        })
        .await?;
        let reader = storage.begin_read().await?;
        assert!(reader.roster_item(&alice, &dave).await?.is_none());
        assert!(reader.roster_item(&carol, &bob).await?.is_none());
        assert_eq!(reader.roster_item(&alice, &bob).await?, Some(stored));
        Ok(())
    })
}

pub(crate) fn remove_roster_item_returns_the_old_item_and_only_advances_an_existing_roster<
    S: Storage,
>(
    storage: S,
) -> TestResult {
    let owner = key("alice@example.com")?;
    let contact = jid("bob@example.com")?;
    let stored = item_with_subscription(
        "bob@example.com",
        Some("Bob"),
        &["Friends"],
        RosterSubscription {
            state: SubscriptionState::Both,
            pending_out: false,
            approved: true,
        },
    )?;
    block_on(async {
        write(&storage, async |tx| {
            tx.put_roster_item(&owner, &stored).await
        })
        .await?;
        let mut writer = storage.begin_write().await?;
        let removed = writer
            .remove_roster_item(&owner, &contact)
            .await?
            .ok_or("missing removal")?;
        assert_eq!(removed.version.get(), 2);
        assert_eq!(removed.value, stored);
        assert!(writer.roster_item(&owner, &contact).await?.is_none());
        assert!(writer.remove_roster_item(&owner, &contact).await?.is_none());
        assert_eq!(writer.roster(&owner).await?.version, removed.version);
        writer.commit().await?;

        let snapshot = read(&storage, async |tx| tx.roster(&owner).await).await?;
        assert_eq!(snapshot.version.get(), 2);
        assert!(snapshot.items.is_empty());
        Ok(())
    })
}

pub(crate) fn removing_a_missing_item_writes_nothing<S: Storage>(storage: S) -> TestResult {
    let alice = key("alice@example.com")?;
    let bob = jid("bob@example.com")?;
    block_on(async {
        assert!(
            write(&storage, async |tx| {
                tx.remove_roster_item(&alice, &bob).await
            })
            .await?
            .is_none()
        );
        let snapshot = read(&storage, async |tx| tx.roster(&alice).await).await?;
        assert_eq!(snapshot.version, RosterVersion::default());
        assert!(snapshot.items.is_empty());
        Ok(())
    })
}

pub(crate) fn pending_requests_are_deduplicated_by_sender_and_returned_in_sender_order<
    S: Storage,
>(
    storage: S,
) -> TestResult {
    let owner = key("alice@example.com")?;
    let carol = key("carol@example.com")?;
    let bob = jid("bob@example.com")?;
    let dave = jid("dave@example.com")?;
    let zara = jid("zara@example.com")?;
    let first = pending("bob@example.com", b"<presence id='first'/>")?;
    let last = pending("bob@example.com", b"<presence id='last'/>")?;
    let from_zara = pending("zara@example.com", b"<presence id='zara'/>")?;
    block_on(async {
        let mut writer = storage.begin_write().await?;
        writer
            .put_pending_request(&owner, from_zara.clone())
            .await?;
        writer.put_pending_request(&owner, first).await?;
        writer.put_pending_request(&owner, last.clone()).await?;
        writer.commit().await?;

        let reader = storage.begin_read().await?;
        let requests = reader.pending_requests(&owner).await?;
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].sender, bob);
        assert_eq!(requests[0].stanza.as_ref(), b"<presence id='last'/>");
        assert_eq!(requests[1].sender, zara);
        assert_eq!(reader.pending_request(&owner, &bob).await?, Some(last));
        assert_eq!(
            reader.pending_request(&owner, &zara).await?,
            Some(from_zara)
        );
        assert!(reader.pending_request(&owner, &dave).await?.is_none());
        assert!(reader.pending_requests(&carol).await?.is_empty());
        assert!(reader.pending_request(&carol, &bob).await?.is_none());
        assert_eq!(
            reader.roster(&owner).await?.version,
            RosterVersion::default()
        );
        Ok(())
    })
}

pub(crate) fn remove_pending_request_reports_existence_and_leaves_items_and_versions_untouched<
    S: Storage,
>(
    storage: S,
) -> TestResult {
    let owner = key("alice@example.com")?;
    let bob = jid("bob@example.com")?;
    let stored = item("bob@example.com", Some("Bob"), &[])?;
    block_on(async {
        let mut writer = storage.begin_write().await?;
        writer.put_roster_item(&owner, &stored).await?;
        writer
            .put_pending_request(&owner, pending("bob@example.com", b"<presence/>")?)
            .await?;
        writer.commit().await?;

        let mut writer = storage.begin_write().await?;
        assert!(writer.remove_pending_request(&owner, &bob).await?);
        assert!(!writer.remove_pending_request(&owner, &bob).await?);
        writer.commit().await?;

        let reader = storage.begin_read().await?;
        assert!(reader.pending_requests(&owner).await?.is_empty());
        assert!(reader.pending_request(&owner, &bob).await?.is_none());
        let snapshot = reader.roster(&owner).await?;
        assert_eq!(snapshot.version.get(), 1);
        assert_eq!(snapshot.items, [stored]);
        Ok(())
    })
}

pub(crate) fn clear_roster_removes_one_owners_items_version_and_pending_requests<S: Storage>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let carol = key("carol@example.com")?;
    let bob = jid("bob@example.com")?;
    let restored = item("bob@example.com", None, &[])?;
    block_on(async {
        let mut writer = storage.begin_write().await?;
        for owner in [&alice, &carol] {
            writer
                .put_roster_item(owner, &item("bob@example.com", None, &[])?)
                .await?;
            writer
                .put_roster_item(owner, &item("dave@example.com", None, &[])?)
                .await?;
            writer
                .put_pending_request(owner, pending("bob@example.com", b"<presence/>")?)
                .await?;
        }
        writer.commit().await?;

        write(&storage, async |tx| tx.clear_roster(&alice).await).await?;
        let reader = storage.begin_read().await?;
        let cleared = reader.roster(&alice).await?;
        assert_eq!(cleared.version, RosterVersion::default());
        assert!(cleared.items.is_empty());
        assert!(reader.roster_item(&alice, &bob).await?.is_none());
        assert!(reader.pending_requests(&alice).await?.is_empty());
        assert!(reader.pending_request(&alice, &bob).await?.is_none());
        let kept = reader.roster(&carol).await?;
        assert_eq!(kept.version.get(), 2);
        assert_eq!(kept.items.len(), 2);
        assert_eq!(reader.pending_requests(&carol).await?.len(), 1);
        drop(reader);

        let version = write(&storage, async |tx| {
            tx.put_roster_item(&alice, &restored).await
        })
        .await?;
        assert_eq!(version.get(), 1);
        Ok(())
    })
}
