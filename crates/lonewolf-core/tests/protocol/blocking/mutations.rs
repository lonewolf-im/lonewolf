// SPDX-License-Identifier: Apache-2.0

use std::fmt::Write;

use lonewolf_storage::blocking::MAX_BLOCKLIST_ITEMS;
use quick_xml::escape::escape;

use super::expect_list;
use crate::support::xml::Element;
use crate::support::{C2sSuite, Client, PASSWORD, TestResult, barrier};

const BLOCKING: &str = "urn:xmpp:blocking";
const PEER: &str = "<item jid='peer.example'/>";
const ZOE: &str = "<item jid='zoe@example.org/Desk'/>";

pub(super) fn fetch(client: &mut Client, items: &str) -> TestResult {
    client.send("<iq type='get' id='list'><blocklist xmlns='urn:xmpp:blocking'/></iq>")?;
    expect_list(
        client,
        "list",
        &format!("<blocklist xmlns='{BLOCKING}'>{items}</blocklist>"),
    )
}

pub(super) fn send_change(client: &mut Client, command: &str, items: &str) -> TestResult {
    client.send(&format!(
        "<iq type='set' id='change'><{command} xmlns='{BLOCKING}'>{items}</{command}></iq>"
    ))
}

pub(super) fn assert_result(reply: &Element) {
    reply.assert_name("jabber:client", "iq");
    assert_eq!(reply.attribute("type"), Some("result"), "{reply:?}");
    assert_eq!(reply.attribute("id"), Some("change"), "{reply:?}");
    assert!(reply.children.is_empty(), "{reply:?}");
}

pub(super) fn push_id<'a>(
    push: &'a Element,
    resource: &str,
    command: &str,
    expected: &[&str],
) -> TestResult<&'a str> {
    push.assert_name("jabber:client", "iq");
    assert_eq!(push.attribute("type"), Some("set"), "{push:?}");
    assert_eq!(push.attribute("to"), Some(resource), "{push:?}");
    let id = push.attribute("id").ok_or("missing push ID")?;
    assert!(!id.is_empty());
    assert_ne!(id, "change");
    assert_eq!(push.children.len(), 1, "{push:?}");
    let payload = push.child(BLOCKING, command)?;
    assert!(payload.text.trim().is_empty());
    let mut items = Vec::new();
    for item in &payload.children {
        item.assert_name(BLOCKING, "item");
        assert!(item.children.is_empty());
        assert!(item.text.trim().is_empty());
        items.push(item.attribute("jid").ok_or("missing push item JID")?);
    }
    items.sort_unstable();
    assert_eq!(items, expected);
    Ok(id)
}

#[test]
fn set_pushes_to_all_and_only_live_fetchers() -> TestResult {
    let mut suite = C2sSuite::with_extensions("'blocking'")?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    phone.send("<presence><priority>-1</priority></presence>")?;
    phone.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/phone' to='alice@localhost'><priority>-1</priority></presence>")?;
    fetch(&mut phone, "")?;
    let mut retired = suite.connect("alice", PASSWORD, "tablet")?;
    fetch(&mut retired, "")?;
    retired.close()?;
    let mut rebound = suite.connect("alice", PASSWORD, "tablet")?;
    let mut other = suite.connect("bob", PASSWORD, "desk")?;
    fetch(&mut other, "")?;
    let mut writer = suite.connect("alice", PASSWORD, "desk")?;

    send_change(
        &mut writer,
        "block",
        "<item jid='PEER.EXAMPLE'/><item jid='peer.example'/>",
    )?;
    assert_result(&writer.receive()?);
    let first = phone.receive()?;
    let first_id = push_id(&first, "alice@localhost/phone", "block", &["peer.example"])?;
    phone.send(&format!("<iq type='result' id='{}'/>", escape(first_id)))?;
    barrier(&mut writer)?;
    barrier(&mut phone)?;
    barrier(&mut rebound)?;
    barrier(&mut other)?;

    fetch(&mut writer, PEER)?;
    send_change(&mut writer, "block", PEER)?;
    let reply = writer.receive()?;
    let own_push = if reply.attribute("type") == Some("set") {
        assert_result(&writer.receive()?);
        reply
    } else {
        assert_result(&reply);
        writer.receive()?
    };
    let own_id = push_id(
        &own_push,
        "alice@localhost/desk",
        "block",
        &["peer.example"],
    )?;
    let second = phone.receive()?;
    let second_id = push_id(&second, "alice@localhost/phone", "block", &["peer.example"])?;
    assert_ne!(own_id, first_id);
    assert_ne!(second_id, first_id);
    assert_ne!(own_id, second_id);
    writer.send(&format!("<iq type='error' id='{}'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>", escape(own_id)))?;
    phone.send(&format!("<iq type='result' id='{}'/>", escape(second_id)))?;
    barrier(&mut writer)?;
    barrier(&mut phone)?;
    fetch(&mut rebound, PEER)?;
    fetch(&mut other, "")?;
    writer.close()?;
    other.close()?;
    rebound.close()?;
    phone.close()?;
    suite.stop()
}

#[test]
fn selective_and_global_unblock_notify_fetchers_on_each_request() -> TestResult {
    let mut suite = C2sSuite::with_extensions("'blocking'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut reader = suite.connect("alice", PASSWORD, "phone")?;
    let mut writer = suite.connect("alice", PASSWORD, "desk")?;
    fetch(&mut reader, "")?;
    let contacts = format!("<item jid='friend.example'/>{PEER}{ZOE}");
    let selective = "<item jid='friend.example'/><item jid='missing.example'/><item jid='PEER.EXAMPLE'/><item jid='peer.example'/>";
    for (command, items, pushed, stored) in [
        (
            "block",
            contacts.as_str(),
            &["friend.example", "peer.example", "zoe@example.org/Desk"][..],
            contacts.as_str(),
        ),
        (
            "unblock",
            selective,
            &["friend.example", "missing.example", "peer.example"],
            ZOE,
        ),
        (
            "unblock",
            selective,
            &["friend.example", "missing.example", "peer.example"],
            ZOE,
        ),
        ("unblock", " \n ", &[], ""),
        ("unblock", "", &[], ""),
    ] {
        send_change(&mut writer, command, items)?;
        assert_result(&writer.receive()?);
        let push = reader.receive()?;
        let id = push_id(&push, "alice@localhost/phone", command, pushed)?;
        reader.send(&format!("<iq type='result' id='{}'/>", escape(id)))?;
        fetch(&mut reader, stored)?;
    }
    barrier(&mut writer)?;
    writer.close()?;
    reader.close()?;
    suite.stop()
}

pub(super) fn expect_error(client: &mut Client, error_type: &str, condition: &str) -> TestResult {
    let reply = client.receive()?;
    reply.assert_name("jabber:client", "iq");
    assert_eq!(reply.attribute("type"), Some("error"), "{reply:?}");
    assert_eq!(reply.attribute("id"), Some("change"), "{reply:?}");
    let error = reply.child("jabber:client", "error")?;
    assert_eq!(error.attribute("type"), Some(error_type), "{error:?}");
    error.child("urn:ietf:params:xml:ns:xmpp-stanzas", condition)?;
    Ok(())
}

#[test]
fn malformed_batch_has_no_observable_effect() -> TestResult {
    let mut suite = C2sSuite::with_extensions("'blocking'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut writer = suite.connect("alice", PASSWORD, "desk")?;
    send_change(&mut writer, "block", "")?;
    expect_error(&mut writer, "modify", "bad-request")?;
    send_change(&mut writer, "block", PEER)?;
    assert_result(&writer.receive()?);
    let mut reader = suite.connect("alice", PASSWORD, "phone")?;
    fetch(&mut reader, PEER)?;
    for (command, items, condition) in [
        ("block", "", "bad-request"),
        ("block", "<item/>", "bad-request"),
        ("block", "<item jid=''/>", "bad-request"),
        (
            "block",
            "<item xmlns:q='urn:test' q:jid='a.example'/>",
            "bad-request",
        ),
        ("block", "<item jid='a.example' extra='b'/>", "bad-request"),
        ("block", "<item jid='two@@example.org'/>", "jid-malformed"),
        (
            "block",
            "<item jid='a.example'/><item jid='two@@example.org'/>",
            "jid-malformed",
        ),
        (
            "block",
            "<item xmlns='urn:test' jid='a.example'/>",
            "bad-request",
        ),
        ("unblock", "<unexpected/>", "bad-request"),
        ("unblock", "text", "bad-request"),
        (
            "unblock",
            "<item jid='peer.example'>text</item>",
            "bad-request",
        ),
        (
            "unblock",
            "<item jid='peer.example'><nested/></item>",
            "bad-request",
        ),
        (
            "unblock",
            "<item jid='peer.example'/><item/>",
            "bad-request",
        ),
        ("unblock", "<item jid='two@@example.org'/>", "jid-malformed"),
    ] {
        send_change(&mut writer, command, items)?;
        expect_error(&mut writer, "modify", condition)?;
        barrier(&mut writer)?;
        fetch(&mut reader, PEER)?;
    }
    for target in ["alice@localhost/desk", "someone@localhost"] {
        writer.send(&format!(
            "<iq to='{target}' type='set' id='change'><unblock xmlns='{BLOCKING}'/></iq>"
        ))?;
        expect_error(&mut writer, "auth", "forbidden")?;
        barrier(&mut writer)?;
        fetch(&mut reader, PEER)?;
    }
    writer.close()?;
    reader.close()?;
    suite.stop()
}

#[test]
fn exceeding_the_blocklist_quota_preserves_the_list_and_sends_no_push() -> TestResult {
    let mut suite = C2sSuite::with_extensions("'blocking'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut writer = suite.connect("alice", PASSWORD, "desk")?;
    let mut items = String::new();
    for start in (0..MAX_BLOCKLIST_ITEMS).step_by(64) {
        let offset = items.len();
        for index in start..(start + 64).min(MAX_BLOCKLIST_ITEMS) {
            write!(items, "<item jid='contact{index:04}.example'/>")?;
        }
        send_change(&mut writer, "block", &items[offset..])?;
        assert_result(&writer.receive()?);
    }
    let mut reader = suite.connect("alice", PASSWORD, "phone")?;
    fetch(&mut reader, &items)?;
    send_change(&mut writer, "block", PEER)?;
    expect_error(&mut writer, "wait", "resource-constraint")?;
    barrier(&mut writer)?;
    fetch(&mut reader, &items)?;
    writer.close()?;
    reader.close()?;
    suite.stop()
}
