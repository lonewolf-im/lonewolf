// SPDX-License-Identifier: Apache-2.0

use std::pin::pin;

use futures_executor::block_on;
use lonewolf_util::arena::Arena;
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::{Element, IqType, Stanza, StanzaNamespace, StanzaType};

use super::{BlockChange, BlockError, BlockingReads, BlockingWrites};
use crate::account::{AccountKey, AccountWrites};
use crate::roster::RosterJid;
use crate::tests::{TestResult, jid, key, new_account, poll, write};
use crate::{RedbStorage, Storage, WriteTransaction};

const ALICE: &str = "alice@example.test";
const BOB: &str = "bob@example.test";
const BOB_ADJACENT: &str = "bob@example.test.invalid";
const NAMESPACE: &str = "urn:xmpp:blocking";

async fn is_blocked(
    reader: &impl BlockingReads,
    owner: &AccountKey,
    peer: &str,
) -> TestResult<bool> {
    let mut arena = Arena::try_new(Default::default())?;
    let peer = Jid::parse_in(peer, &mut arena)?;
    Ok(reader.is_blocked(owner, peer.resolve(&arena)?).await?)
}

#[test]
fn prepared_rules_match_only_the_selected_peer() -> TestResult {
    let storage = crate::redb::tests::storage()?;
    let owner = key(ALICE)?;
    let items = [
        jid("Cafe\u{301}@BÜCHER.Example/De\u{301}sk/floor")?,
        jid("BOB@People.Test")?,
        jid("Service.Example.Test/Console/status")?,
        jid("Closed.Example.Test")?,
    ];
    assert_eq!(items[0].as_str(), "café@bücher.example/Désk/floor");
    block_on(async {
        let mut writer = storage.begin_write().await?;
        writer.create_account(new_account(ALICE, 1)?).await?;
        writer
            .change_blocklist(&owner, BlockChange::Block(&items))
            .await?;
        assert!(is_blocked(&writer, &owner, "CAFÉ@XN--BCHER-KVA.EXAMPLE/Désk/floor").await?);
        writer.commit().await?;
        let reader = storage.begin_read().await?;
        for (peer, expected) in [
            ("CAFÉ@XN--BCHER-KVA.EXAMPLE/Désk/floor", true),
            ("cafe\u{301}@BÜCHER.example/De\u{301}sk/floor", true),
            ("café@bücher.example/désk/floor", false),
            ("café@bücher.example/Désk", false),
            ("café@bücher.example", false),
            ("bOb@PEOPLE.test", true),
            ("bob@people.test/Elsewhere", true),
            ("sibling@people.test/Elsewhere", false),
            ("service.example.test/Console/status", true),
            ("service.example.test/console/status", false),
            ("service.example.test", false),
            ("user@service.example.test/Console/status", false),
            ("closed.example.test", true),
            ("closed.example.test/Console", true),
            ("user@closed.example.test", true),
            ("user@closed.example.test/Console", true),
            ("sub.closed.example.test", false),
            ("user@sub.closed.example.test/Console", false),
        ] {
            assert_eq!(is_blocked(&reader, &owner, peer).await?, expected, "{peer}");
        }
        Ok(())
    })
}

#[test]
fn batch_is_atomic_persistent_and_owner_scoped() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("storage.redb");
    let storage = RedbStorage::open(&path)?;
    let owner = key(BOB)?;
    let adjacent = key(BOB_ADJACENT)?;
    let domain = jid("blocked.example.test")?;
    let bare = jid("peer@blocked.example.test")?;
    let full = jid("peer@blocked.example.test/Desk")?;
    let owner_rules = [domain.clone(), bare.clone(), full.clone()];
    let adjacent_rules = [jid(BOB)?];
    block_on(async {
        let empty = storage.begin_read().await?;
        assert!(empty.blocklist(&owner).await?.is_empty());

        let mut writer = storage.begin_write().await?;
        assert!(matches!(
            writer
                .change_blocklist(&owner, BlockChange::Block(&owner_rules))
                .await,
            Err(BlockError::NoAccount)
        ));
        writer.create_account(new_account(BOB, 1)?).await?;
        writer.create_account(new_account(BOB_ADJACENT, 2)?).await?;
        let request = [full.clone(), domain.clone(), full.clone(), bare.clone()];
        let delta = writer
            .change_blocklist(&owner, BlockChange::Block(&request))
            .await?;
        assert_eq!(delta.inserted, owner_rules);
        assert!(delta.removed.is_empty());
        assert_eq!(delta.before_rules().count(), 0);
        assert!(delta.after_rules().eq(&owner_rules));
        writer
            .change_blocklist(&adjacent, BlockChange::Block(&adjacent_rules))
            .await?;
        writer.commit().await?;
        assert!(empty.blocklist(&owner).await?.is_empty());
        let reader = storage.begin_read().await?;
        assert_eq!(reader.blocklist(&owner).await?, owner_rules);
        assert_eq!(reader.blocklist(&adjacent).await?, adjacent_rules);

        let mut aborted = storage.begin_write().await?;
        let request = [domain, full, jid("absent.example.test")?];
        let delta = aborted
            .change_blocklist(&owner, BlockChange::Unblock(&request))
            .await?;
        assert_eq!(delta.removed, [request[0].clone(), request[1].clone()]);
        assert!(delta.inserted.is_empty());
        assert_eq!(delta.before_rules().count(), 3);
        assert!(delta.after_rules().eq(std::iter::once(&bare)));
        assert!(is_blocked(&aborted, &owner, "peer@blocked.example.test/Desk").await?);
        assert!(!is_blocked(&aborted, &owner, "other@blocked.example.test/Desk").await?);
        drop(aborted);
        assert_eq!(
            storage.begin_read().await?.blocklist(&owner).await?,
            owner_rules
        );
        TestResult::Ok(())
    })?;
    drop(storage);

    let reopened = RedbStorage::open(&path)?;
    block_on(async {
        assert_eq!(
            reopened.begin_read().await?.blocklist(&owner).await?,
            owner_rules
        );
        let mut first = reopened.begin_write().await?;
        let first_item = [jid("aaa.example.test")?];
        let second_item = [jid("zzz.example.test")?];
        let mut second = pin!(reopened.begin_write());
        assert!(poll(second.as_mut()).is_pending());
        first
            .change_blocklist(&owner, BlockChange::Block(&first_item))
            .await?;
        first.commit().await?;
        let mut second = second.await?;
        let delta = second
            .change_blocklist(&owner, BlockChange::Block(&second_item))
            .await?;
        assert!(delta.before_rules().any(|rule| rule == &first_item[0]));
        second.commit().await?;

        let prior = reopened.begin_read().await?;
        let expected = [&first_item[..], &owner_rules[..], &second_item[..]].concat();
        assert_eq!(prior.blocklist(&owner).await?, expected);
        let cleared = write(&reopened, async |writer| {
            writer.change_blocklist(&owner, BlockChange::Clear).await
        })
        .await?;
        assert_eq!(cleared.removed, expected);
        assert!(cleared.before_rules().eq(&expected));
        assert_eq!(cleared.after_rules().count(), 0);
        assert_eq!(prior.blocklist(&owner).await?, expected);
        let current = reopened.begin_read().await?;
        assert!(current.blocklist(&owner).await?.is_empty());
        assert_eq!(current.blocklist(&adjacent).await?, adjacent_rules);
        Ok(())
    })
}

#[test]
fn blocklist_count_limit_accepts_exactly_1024_distinct_rules() -> TestResult {
    let storage = crate::redb::tests::storage()?;
    let owner = key(ALICE)?;
    let rules = (0..1025)
        .map(|index| jid(&format!("contact{index:04}@example.test")))
        .collect::<TestResult<Vec<_>>>()?;
    block_on(async {
        let mut writer = storage.begin_write().await?;
        writer.create_account(new_account(ALICE, 1)?).await?;
        let (allowed, over) = rules.split_at(1024);
        let first = &allowed[..1023];
        writer
            .change_blocklist(&owner, BlockChange::Block(first))
            .await?;
        assert!(matches!(
            writer
                .change_blocklist(&owner, BlockChange::Block(&rules[1023..]))
                .await,
            Err(BlockError::QuotaExceeded)
        ));
        assert_eq!(writer.blocklist(&owner).await?, first);
        let delta = writer
            .change_blocklist(&owner, BlockChange::Block(allowed))
            .await?;
        assert_eq!(delta.inserted, &allowed[1023..]);
        let duplicate = writer
            .change_blocklist(&owner, BlockChange::Block(allowed))
            .await?;
        assert!(duplicate.inserted.is_empty());
        assert_eq!(writer.blocklist(&owner).await?, allowed);
        assert!(matches!(
            writer
                .change_blocklist(&owner, BlockChange::Block(over))
                .await,
            Err(BlockError::QuotaExceeded)
        ));
        writer
            .change_blocklist(&owner, BlockChange::Unblock(&allowed[..1]))
            .await?;
        writer
            .change_blocklist(&owner, BlockChange::Block(over))
            .await?;
        writer.commit().await?;
        assert_eq!(
            storage.begin_read().await?.blocklist(&owner).await?,
            &rules[1..]
        );
        Ok(())
    })
}

fn render_result(items: &[RosterJid]) -> TestResult<String> {
    let mut arena = Arena::try_new(Default::default())?;
    let mut children = Vec::with_capacity(items.len());
    for jid in items {
        children.push(
            Element::builder_in("item", NAMESPACE, &mut arena)?
                .attribute("jid", "", jid.as_str())?
                .build()?,
        );
    }
    let mut blocklist = Element::builder_in("blocklist", NAMESPACE, &mut arena)?;
    for child in children {
        blocklist = blocklist.child(child)?;
    }
    let payload = blocklist.build()?;
    let stanza = Stanza::builder_in(
        StanzaType::Iq(IqType::Result),
        StanzaNamespace::Client,
        &mut arena,
    )
    .id(Some("blocks"))?
    .child(payload)?
    .build()?;
    let mut xml = String::new();
    stanza.resolve(&arena)?.write_xml(&mut xml)?;
    Ok(xml)
}

fn serialized_items_len(items: &[RosterJid]) -> TestResult<usize> {
    let xml = render_result(items)?;
    let content = xml
        .split_once("<blocklist xmlns=\"urn:xmpp:blocking\">")
        .ok_or("missing blocklist")?
        .1;
    Ok(content
        .strip_suffix("</blocklist></iq>")
        .ok_or("missing blocklist end")?
        .len())
}

#[test]
fn blocklist_bytes_limit_counts_the_actual_escaped_item_xml() -> TestResult {
    let storage = crate::redb::tests::storage()?;
    let owner = key(ALICE)?;
    let mut rules = Vec::new();
    let special = "&".repeat(150);
    for index in 0..64 {
        let prefix = format!("peer{index:02}@example.test/{special}<>\"'Å");
        let encoded = serialized_items_len(&[jid(&prefix)?])?;
        rules.push(jid(&format!("{prefix}{}", "x".repeat(1024 - encoded)))?);
    }
    assert_eq!(serialized_items_len(&rules)?, 65_536);
    let over = jid(&format!("{}x", rules[63].as_str()))?;
    assert_eq!(serialized_items_len(std::slice::from_ref(&over))?, 1025);
    block_on(async {
        let mut writer = storage.begin_write().await?;
        writer.create_account(new_account(ALICE, 1)?).await?;
        writer
            .change_blocklist(&owner, BlockChange::Block(&rules[..62]))
            .await?;
        let overflow = [rules[62].clone(), over];
        assert!(matches!(
            writer
                .change_blocklist(&owner, BlockChange::Block(&overflow))
                .await,
            Err(BlockError::QuotaExceeded)
        ));
        assert_eq!(writer.blocklist(&owner).await?, &rules[..62]);
        writer
            .change_blocklist(&owner, BlockChange::Block(&rules))
            .await?;
        let duplicate = writer
            .change_blocklist(&owner, BlockChange::Block(&rules))
            .await?;
        assert!(duplicate.inserted.is_empty());
        writer.commit().await?;
        let stored = storage.begin_read().await?.blocklist(&owner).await?;
        assert_eq!(stored, rules);
        assert_eq!(serialized_items_len(&stored)?, 65_536);
        Ok(())
    })
}
