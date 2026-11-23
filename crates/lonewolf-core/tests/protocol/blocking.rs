// SPDX-License-Identifier: Apache-2.0

mod addressed;
mod mutations;
mod policy;
mod presence;
mod transitions;

use compio::runtime::Runtime;
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::blocking::{
    BlockChange, BlockingWrites, MAX_BLOCKLIST_ITEM_BYTES, MAX_BLOCKLIST_ITEMS,
};
use lonewolf_storage::roster::RosterJid;
use lonewolf_storage::{RedbStorage, Storage, WriteTransaction};
use lonewolf_util::arena::Arena;
use lonewolf_xmpp::jid::Jid;

use crate::support::{C2sSuite, Client, PASSWORD, TestResult, barrier};
use quick_xml::escape::escape;

pub(crate) fn change_rule(client: &mut Client, command: &str, peer: &str) -> TestResult {
    let item = if peer.is_empty() {
        String::new()
    } else {
        format!("<item jid='{peer}'/>")
    };
    mutations::send_change(client, command, &item)?;
    mutations::assert_result(&client.receive()?);
    barrier(client)
}

fn expect_list(client: &mut Client, id: &str, payload: &str) -> TestResult {
    let reply = client.receive()?;
    reply.assert_name("jabber:client", "iq");
    assert_eq!(reply.attribute("type"), Some("result"), "{reply:?}");
    assert_eq!(reply.attribute("id"), Some(id), "{reply:?}");
    assert_eq!(reply.children.len(), 1, "{reply:?}");
    reply.children[0].assert_xml(payload)
}

fn acknowledge_push(client: &mut Client, to: &str, command: &str, peers: &[&str]) -> TestResult {
    let push = client.receive()?;
    let id = mutations::push_id(&push, to, command, peers)?;
    client.send(&format!("<iq type='result' id='{}'/>", escape(id)))
}

fn other_host_reader(suite: &C2sSuite) -> TestResult<Client> {
    use crate::support::OPEN;
    use rustls::pki_types::ServerName;
    use std::sync::Arc;

    let opening = OPEN.replace("to='localhost'", "to='other.localhost'");
    let mut plain = suite.tcp_client()?;
    plain.open_with(&opening)?;
    plain.features()?;
    let mut client = plain.start_tls_with_identity(
        Arc::clone(&suite.tls),
        ServerName::try_from("other.localhost")?,
    )?;
    client.open_with(&opening)?;
    client.features()?;
    client.authenticate("alice", PASSWORD)?;
    let mut client = client.restart();
    client.open_with(&opening)?;
    client.features()?;
    assert_eq!(client.bind(Some("desk"))?, "alice@other.localhost/desk");
    Ok(client)
}

#[test]
fn list_push_and_restart() -> TestResult {
    use mutations::{assert_result, fetch, send_change};
    const BOB: &str = "<item jid='bob@localhost'/>";
    let hosts = "[hosts.localhost]\nextensions = ['blocking']\n[hosts.'other.localhost']\nextensions=['blocking']\n[hosts.'other.localhost'.tls]\ncertificate_chain_path='certificate.pem'\nprivate_key_path='private-key.pem'";
    let mut suite = C2sSuite::with_hosts(hosts)?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    suite.create_account_jid("alice@other.localhost", PASSWORD)?;
    let mut writer = suite.connect("alice", PASSWORD, "writer")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    let mut other = other_host_reader(&suite)?;
    fetch(&mut other, "")?;
    send_change(&mut writer, "block", BOB)?;
    assert_result(&writer.receive()?);
    bob.send("<message to='alice@localhost/writer' id='attempt'/>")?;
    addressed::checked_error(&mut bob, "message", false)?;
    barrier(&mut writer)?;
    bob.send("<message to='alice@other.localhost/desk' id='other-host'/>")?;
    other.expect_xml("<message xmlns='jabber:client' from='bob@localhost/desk' to='alice@other.localhost/desk' id='other-host'/>")?;

    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    fetch(&mut desk, BOB)?;
    fetch(&mut phone, BOB)?;
    for command in ["block", "unblock"] {
        send_change(
            &mut writer,
            command,
            "<item jid='extra.example'/><item jid='third.example'/>",
        )?;
        assert_result(&writer.receive()?);
        acknowledge_push(
            &mut desk,
            "alice@localhost/desk",
            command,
            &["extra.example", "third.example"],
        )?;
        acknowledge_push(
            &mut phone,
            "alice@localhost/phone",
            command,
            &["extra.example", "third.example"],
        )?;
    }
    send_change(&mut writer, "unblock", "<item jid='bob@localhost'/><item/>")?;
    mutations::expect_error(&mut writer, "modify", "bad-request")?;
    send_change(&mut writer, "block", "")?;
    mutations::expect_error(&mut writer, "modify", "bad-request")?;
    fetch(&mut desk, BOB)?;
    fetch(&mut phone, BOB)?;
    send_change(&mut writer, "unblock", "")?;
    assert_result(&writer.receive()?);
    acknowledge_push(&mut desk, "alice@localhost/desk", "unblock", &[])?;
    acknowledge_push(&mut phone, "alice@localhost/phone", "unblock", &[])?;
    phone.close()?;
    suite.wait_for_closed("stream_end", 1)?;
    let mut rebound = suite.connect("alice", PASSWORD, "phone")?;
    send_change(&mut writer, "block", BOB)?;
    assert_result(&writer.receive()?);
    acknowledge_push(
        &mut desk,
        "alice@localhost/desk",
        "block",
        &["bob@localhost"],
    )?;
    barrier(&mut rebound)?;
    barrier(&mut writer)?;
    fetch(&mut other, "")?;
    for mut client in [writer, desk, rebound, other, bob] {
        client.close()?;
    }
    suite.restart()?;
    let mut reader = suite.connect("alice", PASSWORD, "restored")?;
    fetch(&mut reader, BOB)?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    bob.send("<message to='alice@localhost/restored' id='attempt'/>")?;
    addressed::checked_error(&mut bob, "message", false)?;
    barrier(&mut reader)?;
    reader.close()?;
    bob.close()?;

    let config = suite.fixture_path().join("lonewolf.toml");
    let enabled = std::fs::read_to_string(&config)?;
    assert!(enabled.contains("extensions = ['blocking']"));
    let disabled = enabled.replace("extensions = ['blocking']", "extensions = []");
    std::fs::write(&config, &disabled)?;
    suite.restart()?;
    let mut reader = suite.connect("alice", PASSWORD, "disabled")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    bob.send("<message to='alice@localhost/disabled' id='allowed'/>")?;
    reader.expect_xml("<message xmlns='jabber:client' from='bob@localhost/desk' to='alice@localhost/disabled' id='allowed'/>")?;
    reader.close()?;
    bob.close()?;
    std::fs::write(&config, &enabled)?;
    suite.restart()?;
    let mut reader = suite.connect("alice", PASSWORD, "reenabled")?;
    fetch(&mut reader, BOB)?;
    reader.close()?;
    std::fs::write(&config, &disabled)?;
    suite.restart()?;
    suite.delete_account("alice")?;
    suite.create_account("alice", PASSWORD)?;
    std::fs::write(config, enabled)?;
    suite.restart()?;
    let mut reader = suite.connect("alice", PASSWORD, "recreated")?;
    fetch(&mut reader, "")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    bob.send("<message to='alice@localhost/recreated' id='new-account'/>")?;
    reader.expect_xml("<message xmlns='jabber:client' from='bob@localhost/desk' to='alice@localhost/recreated' id='new-account'/>")?;
    reader.close()?;
    bob.close()?;
    suite.stop()
}

#[test]
fn first_get_orders_its_snapshot_with_overlapping_block_and_unblock() -> TestResult {
    use mutations::{assert_result, fetch, push_id, send_change};
    let mut suite = C2sSuite::with_extensions("'blocking', 'ping'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut writer = suite.connect("alice", PASSWORD, "writer")?;
    let mut reader = suite.connect("alice", PASSWORD, "reader")?;
    let mut witness = suite.connect("alice", PASSWORD, "witness")?;
    fetch(&mut witness, "")?;
    let item = "<item jid='bob@localhost'/>";
    send_change(&mut writer, "block", item)?;
    reader.send("<iq type='get' id='race'><blocklist xmlns='urn:xmpp:blocking'/></iq>")?;
    send_change(&mut writer, "unblock", item)?;
    assert_result(&writer.receive()?);
    assert_result(&writer.receive()?);
    for command in ["block", "unblock"] {
        acknowledge_push(
            &mut witness,
            "alice@localhost/witness",
            command,
            &["bob@localhost"],
        )?;
    }
    let reply = reader.receive()?;
    reply.assert_name("jabber:client", "iq");
    assert_eq!(reply.attribute("id"), Some("race"));
    assert_eq!(reply.attribute("type"), Some("result"));
    assert_eq!(reply.children.len(), 1);
    let list = reply.child("urn:xmpp:blocking", "blocklist")?;
    let blocked = !list.children.is_empty();
    list.assert_xml(&format!(
        "<blocklist xmlns='urn:xmpp:blocking'>{}</blocklist>",
        if blocked { item } else { "" }
    ))?;
    reader.send("<iq type='get' id='complete'><ping xmlns='urn:xmpp:ping'/></iq>")?;
    let mut commands = Vec::new();
    loop {
        let stanza = reader.receive()?;
        stanza.assert_name("jabber:client", "iq");
        if stanza.attribute("id") == Some("complete") {
            assert_eq!(stanza.attribute("type"), Some("result"));
            break;
        }
        let command = &stanza.children.first().ok_or("missing push payload")?.name;
        let id = push_id(
            &stanza,
            "alice@localhost/reader",
            command,
            &["bob@localhost"],
        )?;
        reader.send(&format!("<iq type='result' id='{}'/>", escape(id)))?;
        commands.push(command.clone());
    }
    if blocked {
        assert_eq!(commands, ["unblock"]);
    } else {
        assert!(
            commands.is_empty() || commands == ["block", "unblock"],
            "{commands:?}"
        );
    }
    fetch(&mut reader, "")?;
    for mut client in [writer, witness, reader] {
        client.close()?;
    }
    suite.stop()
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
