// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::discovery::{INFO_NAMESPACE, ITEMS_NAMESPACE};

use crate::support::{C2sSuite, PASSWORD, TestResult};

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
        alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' id='node' from='localhost' to='alice@localhost/desk'><query xmlns='{namespace}' node='urn:lonewolf:test:node'/><error type='cancel'><item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>"))?;
    }
    alice.close()
}

#[test]
fn discovery_sets_are_not_routed() -> TestResult {
    let suite = C2sSuite::with_extensions("'disco'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    for namespace in [INFO_NAMESPACE, ITEMS_NAMESPACE] {
        alice.send(&format!(
            "<iq type='set' to='localhost' id='set'><query xmlns='{namespace}'/></iq>"
        ))?;
        alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' id='set' from='localhost'><query xmlns='{namespace}'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>"))?;
    }
    alice.close()
}

#[test]
fn hosts_without_disco_do_not_answer_discovery() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    for namespace in [INFO_NAMESPACE, ITEMS_NAMESPACE] {
        alice.send(&format!(
            "<iq type='get' to='localhost' id='disabled'><query xmlns='{namespace}'/></iq>"
        ))?;
        alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' id='disabled' from='localhost'><query xmlns='{namespace}'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>"))?;
    }
    alice.close()
}
