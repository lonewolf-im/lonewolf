// SPDX-License-Identifier: Apache-2.0

use std::fs;

use lonewolf_extension::discovery::INFO_NAMESPACE;

use super::{addressed, change_rule, host_reader, mutations};
use crate::support::{C2sSuite, Client, PASSWORD, TestResult, barrier, mutually_subscribe};

fn expect_server_feature(client: &mut Client, domain: &str, count: usize) -> TestResult {
    client.send(&format!(
        "<iq type='get' id='disco1' to='{domain}'><query xmlns='{INFO_NAMESPACE}'/></iq>"
    ))?;
    let reply = client.receive()?;
    reply.assert_name("jabber:client", "iq");
    assert_eq!(reply.attribute("type"), Some("result"), "{reply:?}");
    assert_eq!(reply.attribute("id"), Some("disco1"));
    assert_eq!(reply.attribute("from"), Some(domain));
    assert_eq!(
        reply.attribute("to"),
        Some(format!("alice@{domain}/desk").as_str())
    );
    let query = reply.child(INFO_NAMESPACE, "query")?;
    let identity = query.child(INFO_NAMESPACE, "identity")?;
    assert_eq!(identity.attribute("category"), Some("server"));
    assert_eq!(identity.attribute("type"), Some("im"));
    let features = query.children.iter().filter(|child| {
        child.namespace == INFO_NAMESPACE
            && child.name == "feature"
            && child.attribute("var") == Some("urn:xmpp:blocking")
    });
    assert_eq!(features.count(), count, "{reply:?}");
    Ok(())
}

#[test]
fn blocking_is_default_and_advertised_per_host() -> TestResult {
    let mut suite = C2sSuite::with_hosts(
        "[hosts.localhost]
         [hosts.'other.localhost']
         extensions = ['disco']
         [hosts.'other.localhost'.tls]
         certificate_chain_path = 'certificate.pem'
         private_key_path = 'private-key.pem'
         [hosts.'enabled.localhost']
         extensions = ['disco', 'blocking']
         [hosts.'enabled.localhost'.tls]
         certificate_chain_path = 'certificate.pem'
         private_key_path = 'private-key.pem'",
    )?;
    for account in [
        "alice@localhost",
        "bob@localhost",
        "alice@other.localhost",
        "alice@enabled.localhost",
    ] {
        suite.create_account_jid(account, PASSWORD)?;
    }
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut enabled = host_reader(&suite, "enabled.localhost")?;
    let mut disabled = host_reader(&suite, "other.localhost")?;
    expect_server_feature(&mut alice, "localhost", 1)?;
    expect_server_feature(&mut enabled, "enabled.localhost", 1)?;
    expect_server_feature(&mut disabled, "other.localhost", 0)?;

    let item = "<item jid='private.example'/>";
    for owner in [&mut alice, &mut enabled] {
        mutations::send_change(owner, "block", item)?;
        mutations::assert_result(&owner.receive()?);
        mutations::fetch(owner, item)?;
    }
    disabled.send("<iq type='get' id='change'><blocklist xmlns='urn:xmpp:blocking'/></iq>")?;
    mutations::expect_error(&mut disabled, "cancel", "service-unavailable")?;
    mutations::send_change(&mut disabled, "block", item)?;
    mutations::expect_error(&mut disabled, "cancel", "service-unavailable")?;

    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    mutually_subscribe(&mut alice, "alice", &mut bob, "bob")?;
    bob.send("<iq type='get' to='alice@localhost' id='account'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
    bob.expect_xml("<iq xmlns='jabber:client' type='result' id='account' from='alice@localhost' to='bob@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='account' type='registered'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/disco#items'/><feature var='urn:xmpp:ping'/><feature var='vcard-temp'/></query></iq>")?;
    for mut client in [alice, bob, enabled, disabled] {
        client.close()?;
    }
    suite.stop()
}

#[test]
fn reenabled_blocking_enforces_persisted_rules_before_owner_fetch_without_disco() -> TestResult {
    let mut suite = C2sSuite::with_hosts("[hosts.localhost]")?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let mut owner = suite.connect("alice", PASSWORD, "desk")?;
    change_rule(&mut owner, "block", "bob@localhost")?;
    owner.close()?;

    let config = suite.fixture_path().join("lonewolf.toml");
    let original = fs::read_to_string(&config)?;
    let (prefix, suffix) = original
        .split_once("[hosts.localhost]\n")
        .ok_or("missing host configuration")?;
    fs::write(
        &config,
        format!("{prefix}[hosts.localhost]\nextensions = ['disco']\n{suffix}"),
    )?;
    suite.restart()?;
    let mut owner = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    bob.send("<message to='alice@localhost/desk' id='disabled'/>")?;
    owner.expect_xml("<message xmlns='jabber:client' from='bob@localhost/desk' to='alice@localhost/desk' id='disabled'/>")?;
    owner.close()?;
    bob.close()?;

    fs::write(
        config,
        format!("{prefix}[hosts.localhost]\nextensions = ['blocking']\n{suffix}"),
    )?;
    suite.restart()?;
    let mut owner = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    bob.send("<message to='alice@localhost/desk' id='attempt'/>")?;
    addressed::checked_error(&mut bob, "message", false)?;
    barrier(&mut owner)?;
    owner.send("<iq type='get' to='localhost' id='change'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
    mutations::expect_error(&mut owner, "cancel", "service-unavailable")?;
    mutations::fetch(&mut owner, "<item jid='bob@localhost'/>")?;
    owner.close()?;
    bob.close()?;
    suite.stop()
}
