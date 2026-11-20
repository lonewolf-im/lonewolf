// SPDX-License-Identifier: Apache-2.0

mod addressed;
mod mutations;
mod presence;

use compio::runtime::Runtime;
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::blocking::{
    BlockChange, BlockingWrites, MAX_BLOCKLIST_ITEM_BYTES, MAX_BLOCKLIST_ITEMS,
};
use lonewolf_storage::roster::RosterJid;
use lonewolf_storage::{RedbStorage, Storage, WriteTransaction};
use lonewolf_util::arena::Arena;
use lonewolf_xmpp::jid::Jid;

use crate::support::{C2sSuite, Client, PASSWORD, TestResult};

fn expect_list(client: &mut Client, id: &str, payload: &str) -> TestResult {
    let reply = client.receive()?;
    reply.assert_name("jabber:client", "iq");
    assert_eq!(reply.attribute("type"), Some("result"), "{reply:?}");
    assert_eq!(reply.attribute("id"), Some(id), "{reply:?}");
    assert_eq!(reply.children.len(), 1, "{reply:?}");
    reply.children[0].assert_xml(payload)
}

#[test]
fn blocklist_get_returns_only_the_owners_prepared_items() -> TestResult {
    let mut suite = C2sSuite::with_extensions("'blocking'")?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='get' id='empty'><blocklist xmlns='urn:xmpp:blocking'/></iq>")?;
    expect_list(
        &mut alice,
        "empty",
        "<blocklist xmlns='urn:xmpp:blocking'/>",
    )?;
    alice.close()?;
    suite.stop()?;

    {
        let store = RedbStorage::open(suite.fixture_path().join("data/lonewolf.dat"))?;
        let mut arena = Arena::try_new(Default::default())?;
        let owner =
            AccountKey::try_from(Jid::parse_in("alice@localhost", &mut arena)?.resolve(&arena)?)?;
        let mut rules = Vec::new();
        for text in [
            "Zoe@EXAMPLE.org/Desk",
            "PEER.EXAMPLE",
            "zoe@example.org/Desk",
        ] {
            rules.push(RosterJid::from(
                Jid::parse_in(text, &mut arena)?.resolve(&arena)?,
            ));
        }
        Runtime::new()?.block_on(async {
            let mut tx = store.begin_write().await?;
            tx.change_blocklist(&owner, BlockChange::Block(&rules))
                .await?;
            tx.commit().await?;
            TestResult::Ok(())
        })?;
    }
    suite.restart()?;
    let mut alice = suite.connect("alice", PASSWORD, "phone")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    let populated = "<blocklist xmlns='urn:xmpp:blocking'><item jid='peer.example'/><item jid='zoe@example.org/Desk'/></blocklist>";
    alice.send("<iq type='get' id='mine'><blocklist xmlns='urn:xmpp:blocking'/></iq>")?;
    expect_list(&mut alice, "mine", populated)?;
    alice.send("<iq type='get' id='own-bare' to='alice@localhost'><blocklist xmlns='urn:xmpp:blocking'> \n </blocklist></iq>")?;
    expect_list(&mut alice, "own-bare", populated)?;
    bob.send("<iq type='get' id='other'><blocklist xmlns='urn:xmpp:blocking'/></iq>")?;
    expect_list(&mut bob, "other", "<blocklist xmlns='urn:xmpp:blocking'/>")?;
    bob.close()?;
    alice.close()?;
    suite.stop()
}

#[test]
fn blocklist_get_rejects_invalid_content_and_non_owner_destinations() -> TestResult {
    let mut suite = C2sSuite::with_extensions("'blocking'")?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    for content in [
        "<item jid='peer.example'/>",
        "<unrelated xmlns='urn:test'/>",
        "text",
    ] {
        alice.send(&format!("<iq type='get' id='invalid'><blocklist xmlns='urn:xmpp:blocking'>{content}</blocklist></iq>"))?;
        let reply = alice.receive()?;
        reply.assert_name("jabber:client", "iq");
        assert_eq!(reply.attribute("type"), Some("error"), "{reply:?}");
        assert_eq!(reply.attribute("id"), Some("invalid"), "{reply:?}");
        reply
            .child("jabber:client", "error")?
            .child("urn:ietf:params:xml:ns:xmpp-stanzas", "bad-request")?;
    }
    for target in [
        "alice@localhost/desk",
        "bob@localhost",
        "unregistered@localhost",
    ] {
        alice.send(&format!(
            "<iq type='get' id='foreign' to='{target}'><blocklist xmlns='urn:xmpp:blocking'/></iq>"
        ))?;
        let reply = alice.receive()?;
        reply.assert_name("jabber:client", "iq");
        assert_eq!(reply.attribute("type"), Some("error"), "{reply:?}");
        assert_eq!(reply.attribute("id"), Some("foreign"), "{reply:?}");
        assert_eq!(reply.children.len(), 1, "{reply:?}");
        let error = reply.child("jabber:client", "error")?;
        assert_eq!(error.attribute("type"), Some("auth"), "{error:?}");
        error.child("urn:ietf:params:xml:ns:xmpp-stanzas", "forbidden")?;
    }
    alice.close()?;
    suite.stop()
}

#[test]
fn full_blocklist_fits_in_one_client_reply() -> TestResult {
    let mut suite = C2sSuite::with_extensions("'blocking'")?;
    suite.create_account("alice", PASSWORD)?;
    suite.stop()?;
    let items = {
        let store = RedbStorage::open(suite.fixture_path().join("data/lonewolf.dat"))?;
        let mut arena = Arena::try_new(Default::default())?;
        let owner =
            AccountKey::try_from(Jid::parse_in("alice@localhost", &mut arena)?.resolve(&arena)?)?;
        let item_bytes = MAX_BLOCKLIST_ITEM_BYTES / MAX_BLOCKLIST_ITEMS;
        let mut items = Vec::with_capacity(MAX_BLOCKLIST_ITEMS);
        for index in 0..MAX_BLOCKLIST_ITEMS {
            let prefix = format!("contact{index:04}@example.org/Desk&");
            let padding =
                item_bytes - (prefix.len() - 1 + "&amp;".len() + "<item jid=\"\"/>".len());
            let jid = Jid::parse_in(&format!("{prefix}{}", "x".repeat(padding)), &mut arena)?;
            items.push(RosterJid::from(jid.resolve(&arena)?));
        }
        Runtime::new()?.block_on(async {
            let mut tx = store.begin_write().await?;
            tx.change_blocklist(&owner, BlockChange::Block(&items))
                .await?;
            tx.commit().await?;
            TestResult::Ok(())
        })?;
        items
    };
    suite.restart()?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='get' id='full'><blocklist xmlns='urn:xmpp:blocking'/></iq>")?;
    let reply = alice.receive()?;
    reply.assert_name("jabber:client", "iq");
    assert_eq!(reply.attribute("type"), Some("result"));
    assert_eq!(reply.attribute("id"), Some("full"));
    assert_eq!(reply.children.len(), 1);
    let blocklist = reply.child("urn:xmpp:blocking", "blocklist")?;
    assert_eq!(blocklist.children.len(), items.len());
    for (item, jid) in blocklist.children.iter().zip(&items) {
        item.assert_name("urn:xmpp:blocking", "item");
        assert_eq!(item.attribute("jid"), Some(jid.as_str()));
        assert!(item.children.is_empty());
    }
    alice.close()?;
    suite.stop()
}
