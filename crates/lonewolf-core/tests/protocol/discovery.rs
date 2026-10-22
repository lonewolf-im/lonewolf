// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use rustls::pki_types::ServerName;

use lonewolf_extension::discovery::{INFO_NAMESPACE, ITEMS_NAMESPACE};

use crate::support::{C2sSuite, OPEN, PASSWORD, TestResult, mutually_subscribe, toggle};

#[test]
fn default_hosts_answer_discovery() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='get' to='localhost' id='host-info'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='host-info' from='localhost' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='server' type='im'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/disco#items'/><feature var='jabber:iq:roster'/><feature var='msgoffline'/><feature var='urn:xmpp:ping'/><feature var='vcard-temp'/></query></iq>")?;
    alice.send("<iq type='get' to='alice@localhost' id='account-info'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='account-info' from='alice@localhost' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='account' type='registered'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/disco#items'/><feature var='urn:xmpp:ping'/><feature var='vcard-temp'/></query></iq>")?;
    alice.close()
}

#[test]
fn discovery_and_vcard_quotas_follow_each_hosts_selection() -> TestResult {
    for (local, remote) in [
        ("'disco', 'vcard'", "'vcard', 'disco'"),
        ("'vcard', 'disco'", "'disco', 'vcard'"),
    ] {
        let suite = C2sSuite::with_hosts(&format!(
            "[hosts.localhost]\nextensions=[{local}]\n[hosts.localhost.vcard]\nmax_bytes=512\n[hosts.'other.localhost']\nextensions=[{remote}]\n[hosts.'other.localhost'.vcard]\nmax_bytes=1\n[hosts.'other.localhost'.tls]\ncertificate_chain_path='certificate.pem'\nprivate_key_path='private-key.pem'\n"
        ))?;
        suite.create_account("alice", PASSWORD)?;
        suite.create_account_jid("alice@other.localhost", PASSWORD)?;
        let mut alice = suite.connect("alice", PASSWORD, "desk")?;
        let opening = OPEN.replace("to='localhost'", "to='other.localhost'");
        let mut plain = suite.tcp_client()?;
        plain.open_with(&opening)?;
        plain.features()?;
        let mut other = plain.start_tls_with_identity(
            Arc::clone(&suite.tls),
            ServerName::try_from("other.localhost")?,
        )?;
        other.open_with(&opening)?;
        other.features()?;
        other.authenticate("alice", PASSWORD)?;
        let mut other = other.restart();
        other.open_with(&opening)?;
        other.features()?;
        assert_eq!(other.bind(Some("desk"))?, "alice@other.localhost/desk");
        for (client, domain, fits) in [
            (&mut alice, "localhost", true),
            (&mut other, "other.localhost", false),
        ] {
            for (target, category, kind) in [
                (domain.to_owned(), "server", "im"),
                (format!("alice@{domain}"), "account", "registered"),
            ] {
                client.send(&format!("<iq type='get' to='{target}' id='info'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>"))?;
                client.expect_xml(&format!("<iq xmlns='jabber:client' type='result' from='{target}' to='alice@{domain}/desk' id='info'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='{category}' type='{kind}'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/disco#items'/><feature var='vcard-temp'/></query></iq>"))?;
            }
            client.send("<iq type='set' id='write'><vCard xmlns='vcard-temp'/></iq>")?;
            if fits {
                client.expect_xml(&format!(
                    "<iq xmlns='jabber:client' type='result' id='write' to='alice@{domain}/desk'/>"
                ))?;
            } else {
                client.expect_xml(&format!("<iq xmlns='jabber:client' type='error' id='write' to='alice@{domain}/desk'><error type='wait'><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>vCard exceeds the 1-byte limit, including XML and Base64 data. Use a smaller avatar or reduce profile data.</text></error></iq>"))?;
            }
        }
        other.send(
            "<iq type='get' to='alice@localhost' id='public'><vCard xmlns='vcard-temp'/></iq>",
        )?;
        other.expect_xml("<iq xmlns='jabber:client' type='result' from='alice@localhost' to='alice@other.localhost/desk' id='public'><vCard xmlns='vcard-temp' xmlns:stream='http://etherx.jabber.org/streams' xml:lang='' xml:space='default'/></iq>")?;
        alice.close()?;
        other.close()?;
    }
    Ok(())
}

#[test]
fn public_vcards_do_not_make_default_account_discovery_public() -> TestResult {
    let suite = C2sSuite::start()?;
    for user in ["alice", "bob"] {
        suite.create_account(user, PASSWORD)?;
    }
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    alice.send("<iq type='set' id='write'><vCard xmlns='vcard-temp'/></iq>")?;
    alice.expect_xml(
        "<iq xmlns='jabber:client' type='result' id='write' to='alice@localhost/desk'/>",
    )?;
    bob.send("<iq type='get' to='alice@localhost' id='public'><vCard xmlns='vcard-temp'/></iq>")?;
    bob.expect_xml("<iq xmlns='jabber:client' type='result' from='alice@localhost' to='bob@localhost/desk' id='public'><vCard xmlns='vcard-temp' xmlns:stream='http://etherx.jabber.org/streams' xml:lang='' xml:space='default'/></iq>")?;
    bob.send("<iq type='get' to='alice@localhost' id='private'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
    bob.expect_xml("<iq xmlns='jabber:client' type='error' from='alice@localhost' to='bob@localhost/desk' id='private'><query xmlns='http://jabber.org/protocol/disco#info'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>")?;
    alice.close()?;
    bob.close()
}

#[test]
fn host_info_lists_the_server_identity_and_disco_features() -> TestResult {
    let suite = C2sSuite::with_extensions("'disco'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='get' to='localhost' id='info'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='info' from='localhost' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='server' type='im'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/disco#items'/></query></iq>")?;
    alice.close()
}

#[test]
fn host_info_lists_features_of_enabled_extensions() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster', 'offline', 'disco'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='get' to='localhost' id='info'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='info' from='localhost' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='server' type='im'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/disco#items'/><feature var='jabber:iq:roster'/><feature var='msgoffline'/></query></iq>")?;
    alice.close()?;

    let suite = C2sSuite::with_extensions("'offline', 'disco'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='get' to='localhost' id='info'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='info' from='localhost' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='server' type='im'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/disco#items'/><feature var='msgoffline'/></query></iq>")?;
    alice.close()
}

#[test]
fn host_items_list_hosted_service_domains() -> TestResult {
    let suite = C2sSuite::with_extensions("'disco', 'test-service'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='get' to='localhost' id='items'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='items' from='localhost' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#items'><item jid='echo.localhost'/></query></iq>")?;
    alice.close()
}

#[test]
fn host_items_without_services_are_empty() -> TestResult {
    let suite = C2sSuite::with_extensions("'disco'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='get' to='localhost' id='items'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='items' from='localhost' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>")?;
    alice.close()
}

#[test]
fn host_queries_for_a_node_return_item_not_found() -> TestResult {
    let suite = C2sSuite::with_extensions("'disco'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    for namespace in [INFO_NAMESPACE, ITEMS_NAMESPACE] {
        alice.send(&format!("<iq type='get' to='localhost' id='node'><query xmlns='{namespace}' node='urn:lonewolf:test:node'/></iq>"))?;
        alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' id='node' from='localhost' to='alice@localhost/desk'><query xmlns='{namespace}' node='urn:lonewolf:test:node'/><error type='cancel'><item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested item is not available.</text></error></iq>"))?;
    }
    alice.close()
}

#[test]
fn discovery_sets_are_not_routed() -> TestResult {
    let suite = C2sSuite::with_extensions("'disco'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    for target in ["localhost", "alice@localhost"] {
        for namespace in [INFO_NAMESPACE, ITEMS_NAMESPACE] {
            alice.send(&format!(
                "<iq type='set' to='{target}' id='set'><query xmlns='{namespace}'/></iq>"
            ))?;
            alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' id='set' from='{target}'><query xmlns='{namespace}'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>"))?;
        }
    }
    alice.close()
}

#[test]
fn hosts_without_disco_do_not_answer_discovery() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    for target in ["localhost", "alice@localhost"] {
        for namespace in [INFO_NAMESPACE, ITEMS_NAMESPACE] {
            alice.send(&format!(
                "<iq type='get' to='{target}' id='disabled'><query xmlns='{namespace}'/></iq>"
            ))?;
            alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' id='disabled' from='{target}'><query xmlns='{namespace}'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>"))?;
        }
    }
    alice.close()
}

#[test]
fn owners_receive_account_info() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster', 'disco'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send(
        "<iq type='get' id='info'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='info' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='account' type='registered'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/disco#items'/></query></iq>")?;
    alice.send("<iq type='get' to='alice@localhost' id='info'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='info' from='alice@localhost' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='account' type='registered'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/disco#items'/></query></iq>")?;
    alice.close()
}

#[test]
fn account_info_requires_presence_authorization() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster', 'disco'")?;
    for user in ["alice", "bob"] {
        suite.create_account(user, PASSWORD)?;
    }
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    bob.send("<iq type='get' to='alice@localhost' id='info'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
    bob.expect_xml("<iq xmlns='jabber:client' type='error' id='info' from='alice@localhost' to='bob@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#info'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>")?;
    mutually_subscribe(&mut alice, "alice", &mut bob, "bob")?;
    bob.send("<iq type='get' to='alice@localhost' id='info'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
    bob.expect_xml("<iq xmlns='jabber:client' type='result' id='info' from='alice@localhost' to='bob@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='account' type='registered'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/disco#items'/></query></iq>")?;
    alice.close()?;
    bob.close()
}

#[test]
fn missing_and_hidden_accounts_answer_alike() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster', 'disco'")?;
    for user in ["alice", "bob"] {
        suite.create_account(user, PASSWORD)?;
    }
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    for namespace in [INFO_NAMESPACE, ITEMS_NAMESPACE] {
        for node in ["", " node='x'"] {
            let mut replies = Vec::with_capacity(2);
            for target in ["missing", "alice"] {
                bob.send(&format!("<iq type='get' to='{target}@localhost' id='query'><query xmlns='{namespace}'{node}/></iq>"))?;
                let reply = bob.receive()?;
                if namespace == INFO_NAMESPACE {
                    reply.assert_xml(&format!("<iq xmlns='jabber:client' type='error' id='query' from='{target}@localhost' to='bob@localhost/desk'><query xmlns='{namespace}'{node}/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>"))?;
                } else {
                    reply.assert_xml(&format!("<iq xmlns='jabber:client' type='result' id='query' from='{target}@localhost' to='bob@localhost/desk'><query xmlns='{namespace}'{node}/></iq>"))?;
                }
                replies.push(reply);
            }
            assert_eq!(replies[0].children, replies[1].children);
        }
    }
    bob.close()
}

#[test]
fn account_items_list_resources_by_relationship() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster', 'disco'")?;
    for user in ["alice", "bob", "carol"] {
        suite.create_account(user, PASSWORD)?;
    }
    let mut alice_desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut alice_phone = suite.connect("alice", PASSWORD, "phone")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    let mut carol = suite.connect("carol", PASSWORD, "desk")?;
    mutually_subscribe(&mut alice_desk, "alice", &mut bob, "bob")?;
    alice_desk.send("<presence id='avail'/>")?;
    alice_desk.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost' id='avail'/>")?;
    alice_desk.send("<iq type='get' to='alice@localhost' id='items'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>")?;
    alice_desk.expect_xml("<iq xmlns='jabber:client' type='result' id='items' from='alice@localhost' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#items'><item jid='alice@localhost/desk'/><item jid='alice@localhost/phone'/></query></iq>")?;
    alice_desk.send("<iq type='get' id='own-items'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>")?;
    alice_desk.expect_xml("<iq xmlns='jabber:client' type='result' id='own-items' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#items'><item jid='alice@localhost/desk'/><item jid='alice@localhost/phone'/></query></iq>")?;
    bob.send("<iq type='get' to='alice@localhost' id='items'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>")?;
    bob.expect_xml("<iq xmlns='jabber:client' type='result' id='items' from='alice@localhost' to='bob@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#items'><item jid='alice@localhost/desk'/></query></iq>")?;
    carol.send("<iq type='get' to='alice@localhost' id='items'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>")?;
    carol.expect_xml("<iq xmlns='jabber:client' type='result' id='items' from='alice@localhost' to='carol@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>")?;
    alice_phone.close()?;
    suite.wait_for_log("stream disconnected")?;
    alice_desk.send("<iq type='get' to='alice@localhost' id='after-close'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>")?;
    alice_desk.expect_xml("<iq xmlns='jabber:client' type='result' id='after-close' from='alice@localhost' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#items'><item jid='alice@localhost/desk'/></query></iq>")?;
    alice_desk.close()?;
    bob.close()?;
    carol.close()
}

#[test]
fn account_queries_for_a_node() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster', 'disco'")?;
    for user in ["alice", "bob", "carol"] {
        suite.create_account(user, PASSWORD)?;
    }
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut carol = suite.connect("carol", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    mutually_subscribe(&mut alice, "alice", &mut bob, "bob")?;
    for namespace in [INFO_NAMESPACE, ITEMS_NAMESPACE] {
        alice.send(&format!("<iq type='get' to='alice@localhost' id='node'><query xmlns='{namespace}' node='x'/></iq>"))?;
        alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' id='node' from='alice@localhost' to='alice@localhost/desk'><query xmlns='{namespace}' node='x'/><error type='cancel'><item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested item is not available.</text></error></iq>"))?;
    }
    for namespace in [INFO_NAMESPACE, ITEMS_NAMESPACE] {
        bob.send(&format!("<iq type='get' to='alice@localhost' id='node'><query xmlns='{namespace}' node='x'/></iq>"))?;
        bob.expect_xml(&format!("<iq xmlns='jabber:client' type='error' id='node' from='alice@localhost' to='bob@localhost/desk'><query xmlns='{namespace}' node='x'/><error type='cancel'><item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested item is not available.</text></error></iq>"))?;
    }
    carol.send("<iq type='get' to='alice@localhost' id='node'><query xmlns='http://jabber.org/protocol/disco#items' node='x'/></iq>")?;
    carol.expect_xml("<iq xmlns='jabber:client' type='result' id='node' from='alice@localhost' to='carol@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#items' node='x'/></iq>")?;
    carol.send("<iq type='get' to='alice@localhost' id='node'><query xmlns='http://jabber.org/protocol/disco#info' node='x'/></iq>")?;
    carol.expect_xml("<iq xmlns='jabber:client' type='error' id='node' from='alice@localhost' to='carol@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#info' node='x'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>")?;
    alice.close()?;
    bob.close()?;
    carol.close()
}

#[test]
fn without_roster_only_owners_see_account_data() -> TestResult {
    let suite = C2sSuite::with_extensions("'disco'")?;
    for user in ["alice", "bob"] {
        suite.create_account(user, PASSWORD)?;
    }
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    bob.send("<iq type='get' to='alice@localhost' id='info'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
    bob.expect_xml("<iq xmlns='jabber:client' type='error' id='info' from='alice@localhost' to='bob@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#info'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>")?;
    bob.send("<iq type='get' to='alice@localhost' id='items'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>")?;
    bob.expect_xml("<iq xmlns='jabber:client' type='result' id='items' from='alice@localhost' to='bob@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>")?;
    alice.send("<iq type='get' to='alice@localhost' id='info'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='info' from='alice@localhost' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='account' type='registered'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/disco#items'/></query></iq>")?;
    alice.close()?;
    bob.close()
}

#[test]
fn clients_walk_from_host_items_to_service_info() -> TestResult {
    let suite = C2sSuite::with_extensions("'disco', 'test-service'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='get' to='localhost' id='items'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='items' from='localhost' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#items'><item jid='echo.localhost'/></query></iq>")?;
    alice.send("<iq type='get' to='echo.localhost' id='service'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='service' from='echo.localhost' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='component' type='generic' name='Echo'/><feature var='http://jabber.org/protocol/disco#info'/></query></iq>")?;
    alice.close()
}

#[test]
fn discovery_follows_the_target_hosts_extensions() -> TestResult {
    let suite = C2sSuite::with_hosts(
        r#"
[hosts.localhost]
extensions = ["roster", "offline", "disco"]
[hosts."other.localhost"]
extensions = ["disco"]
[hosts."other.localhost".tls]
certificate_chain_path = "certificate.pem"
private_key_path = "private-key.pem"
"#,
    )?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account_jid("bob@other.localhost", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='get' to='other.localhost' id='other'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='other' from='other.localhost' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='server' type='im'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/disco#items'/></query></iq>")?;
    alice.send("<iq type='get' to='localhost' id='local'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='local' from='localhost' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='server' type='im'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/disco#items'/><feature var='jabber:iq:roster'/><feature var='msgoffline'/></query></iq>")?;
    alice.send("<iq type='get' to='bob@other.localhost' id='account'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='account' from='bob@other.localhost' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#info'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>")?;
    alice.close()
}

#[test]
fn policy_runs_before_account_discovery() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster', 'disco', 'test-policy'")?;
    for user in ["alice", "blocked"] {
        suite.create_account(user, PASSWORD)?;
    }
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    toggle(&mut alice, true)?;
    alice.send("<iq type='get' to='blocked@localhost' id='policy'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='policy' from='blocked@localhost'><query xmlns='http://jabber.org/protocol/disco#info'/><error type='modify'><not-acceptable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>A request value exceeds an allowed limit or has an unsupported format.</text><blocked xmlns='urn:lonewolf:test:policy'/></error></iq>")?;
    toggle(&mut alice, false)?;
    alice.send("<iq type='get' to='blocked@localhost' id='disco'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='disco' from='blocked@localhost' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#info'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>")?;
    alice.close()
}

#[test]
fn discovery_requests_to_full_jids_reach_the_resource() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster', 'disco'")?;
    for user in ["alice", "bob"] {
        suite.create_account(user, PASSWORD)?;
    }
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    mutually_subscribe(&mut alice, "alice", &mut bob, "bob")?;
    bob.send("<iq type='get' to='alice@localhost/desk' id='client'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='get' id='client' from='bob@localhost/desk' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
    alice.send("<iq type='result' to='bob@localhost/desk' id='client'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='client' type='pc' name='Desk'/><feature var='urn:lonewolf:test:client'/></query></iq>")?;
    bob.expect_xml("<iq xmlns='jabber:client' type='result' id='client' from='alice@localhost/desk' to='bob@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='client' type='pc' name='Desk'/><feature var='urn:lonewolf:test:client'/></query></iq>")?;
    alice.close()?;
    bob.close()
}

#[test]
fn remote_discovery_targets_are_not_answered() -> TestResult {
    let suite = C2sSuite::with_extensions("'disco'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    for target in ["remote.example", "bob@remote.example"] {
        for namespace in [INFO_NAMESPACE, ITEMS_NAMESPACE] {
            alice.send(&format!(
                "<iq type='get' to='{target}' id='remote'><query xmlns='{namespace}'/></iq>"
            ))?;
            alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' id='remote' from='{target}'><query xmlns='{namespace}'/><error type='cancel'><remote-server-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The server cannot deliver this request to a remote domain.</text></error></iq>"))?;
        }
    }
    alice.close()
}
