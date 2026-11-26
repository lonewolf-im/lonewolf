// SPDX-License-Identifier: Apache-2.0

use crate::support::{C2sSuite, PASSWORD, TestResult, mutually_subscribe};

const UNAVAILABLE: &str = "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error>";
const QUERY: &str = "<query xmlns='jabber:iq:version'/>";

fn reply(os: Option<&str>) -> String {
    let os = os.map(|os| format!("<os>{os}</os>")).unwrap_or_default();
    format!(
        "<query xmlns='jabber:iq:version'><name>Lonewolf</name><version>integration-test</version>{os}</query>"
    )
}

#[test]
fn default_hosts_answer_software_version_queries() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    for payload in [
        QUERY,
        "<v:query xmlns:v='jabber:iq:version'/>",
        "<query xmlns='jabber:iq:version' extra='1'>text</query>",
        "<query xmlns='jabber:iq:version'><name>Spoofed</name><version>0</version><os>none</os></query>",
    ] {
        alice.send(&format!(
            "<iq type='get' to='localhost' id='version'>{payload}</iq>"
        ))?;
        alice.expect_xml(&format!("<iq xmlns='jabber:client' type='result' id='version' from='localhost' to='alice@localhost/desk'>{}</iq>", reply(None)))?;
    }
    alice.close()
}

#[test]
fn operating_system_is_shared_only_when_enabled() -> TestResult {
    for (setting, os) in [
        ("", None),
        ("[hosts.localhost.version]\nshow_os = false", None),
        (
            "[hosts.localhost.version]\nshow_os = true",
            Some(std::env::consts::OS),
        ),
    ] {
        let suite = C2sSuite::with_hosts(&format!(
            "[hosts.localhost]\nextensions = ['version']\n{setting}"
        ))?;
        suite.create_account("alice", PASSWORD)?;
        let mut alice = suite.connect("alice", PASSWORD, "desk")?;
        alice.send(&format!(
            "<iq type='get' to='localhost' id='version'>{QUERY}</iq>"
        ))?;
        alice.expect_xml(&format!("<iq xmlns='jabber:client' type='result' id='version' from='localhost' to='alice@localhost/desk'>{}</iq>", reply(os)))?;
        alice.close()?;
    }
    Ok(())
}

#[test]
fn software_version_follows_the_target_hosts_configuration() -> TestResult {
    for (local_extensions, local_options, other_extensions, local_os, other_enabled) in [
        (
            "'version'",
            "[hosts.localhost.version]\nshow_os = true",
            "'disco'",
            Some(std::env::consts::OS),
            false,
        ),
        ("'disco'", "", "'version'", None, true),
    ] {
        let suite = C2sSuite::with_hosts(&format!(
            "[hosts.localhost]\nextensions = [{local_extensions}]\n{local_options}\n[hosts.\"other.localhost\"]\nextensions = [{other_extensions}]\n[hosts.\"other.localhost\".tls]\ncertificate_chain_path = 'certificate.pem'\nprivate_key_path = 'private-key.pem'"
        ))?;
        suite.create_account("alice", PASSWORD)?;
        let mut alice = suite.connect("alice", PASSWORD, "desk")?;
        for (target, id, enabled, os) in [
            ("localhost", "local", !other_enabled, local_os),
            ("other.localhost", "other", other_enabled, None),
        ] {
            alice.send(&format!(
                "<iq type='get' to='{target}' id='{id}'>{QUERY}</iq>"
            ))?;
            if enabled {
                alice.expect_xml(&format!("<iq xmlns='jabber:client' type='result' id='{id}' from='{target}' to='alice@localhost/desk'>{}</iq>", reply(os)))?;
            } else {
                alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' id='{id}' from='{target}'>{QUERY}{UNAVAILABLE}</iq>"))?;
            }
        }
        alice.close()?;
    }
    Ok(())
}

#[test]
fn software_version_is_not_answered_for_accounts() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster', 'version'")?;
    for name in ["alice", "bob"] {
        suite.create_account(name, PASSWORD)?;
    }
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    for target in ["alice@localhost", "bob@localhost", "missing@localhost"] {
        alice.send(&format!(
            "<iq type='get' to='{target}' id='account'>{QUERY}</iq>"
        ))?;
        alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' id='account' from='{target}'>{QUERY}{UNAVAILABLE}</iq>"))?;
    }
    alice.send(&format!("<iq type='get' id='account'>{QUERY}</iq>"))?;
    alice.expect_xml(&format!(
        "<iq xmlns='jabber:client' type='error' id='account'>{QUERY}{UNAVAILABLE}</iq>"
    ))?;
    mutually_subscribe(&mut alice, "alice", &mut bob, "bob")?;
    alice.send(&format!(
        "<iq type='get' to='bob@localhost' id='account'>{QUERY}</iq>"
    ))?;
    alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' id='account' from='bob@localhost'>{QUERY}{UNAVAILABLE}</iq>"))?;
    alice.close()?;
    bob.close()
}

#[test]
fn software_version_sets_and_nonlocal_targets_keep_generic_errors() -> TestResult {
    let suite = C2sSuite::with_extensions("'version'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send(&format!(
        "<iq type='set' to='localhost' id='set'>{QUERY}</iq>"
    ))?;
    alice.expect_xml(&format!(
        "<iq xmlns='jabber:client' type='error' id='set' from='localhost'>{QUERY}{UNAVAILABLE}</iq>"
    ))?;
    alice.send(&format!(
        "<iq type='get' to='localhost/console' id='nonlocal'>{QUERY}</iq>"
    ))?;
    alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' id='nonlocal' from='localhost/console' to='alice@localhost/desk'>{QUERY}{UNAVAILABLE}</iq>"))?;
    alice.send(&format!(
        "<iq type='get' to='remote.example' id='nonlocal'>{QUERY}</iq>"
    ))?;
    alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' id='nonlocal' from='remote.example'>{QUERY}<error type='cancel'><remote-server-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The server cannot deliver this request to a remote domain.</text></error></iq>"))?;
    alice.close()
}

#[test]
fn version_and_disco_are_independently_selectable() -> TestResult {
    for (extensions, disco, version) in [
        ("'version'", false, true),
        ("'disco'", true, false),
        ("'disco', 'version'", true, true),
        ("'version', 'disco'", true, true),
    ] {
        let suite = C2sSuite::with_extensions(extensions)?;
        suite.create_account("alice", PASSWORD)?;
        let mut alice = suite.connect("alice", PASSWORD, "desk")?;
        alice.send(&format!(
            "<iq type='get' to='localhost' id='version'>{QUERY}</iq>"
        ))?;
        if version {
            alice.expect_xml(&format!("<iq xmlns='jabber:client' type='result' id='version' from='localhost' to='alice@localhost/desk'>{}</iq>", reply(None)))?;
        } else {
            alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' id='version' from='localhost'>{QUERY}{UNAVAILABLE}</iq>"))?;
        }
        alice.send("<iq type='get' to='localhost' id='info'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
        if disco {
            let feature = if version {
                "<feature var='jabber:iq:version'/>"
            } else {
                ""
            };
            alice.expect_xml(&format!("<iq xmlns='jabber:client' type='result' id='info' from='localhost' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='server' type='im'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/disco#items'/>{feature}</query></iq>"))?;
            alice.send("<iq type='get' to='alice@localhost' id='info'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
            alice.expect_xml("<iq xmlns='jabber:client' type='result' id='info' from='alice@localhost' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='account' type='registered'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/disco#items'/></query></iq>")?;
        } else {
            alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' id='info' from='localhost'><query xmlns='http://jabber.org/protocol/disco#info'/>{UNAVAILABLE}</iq>"))?;
        }
        alice.close()?;
    }
    Ok(())
}

#[test]
fn software_version_requests_to_full_jids_reach_the_client() -> TestResult {
    for extensions in ["'roster', 'version'", "'roster'"] {
        let suite = C2sSuite::with_extensions(extensions)?;
        for name in ["alice", "bob"] {
            suite.create_account(name, PASSWORD)?;
        }
        let mut alice = suite.connect("alice", PASSWORD, "desk")?;
        let mut bob = suite.connect("bob", PASSWORD, "desk")?;
        mutually_subscribe(&mut alice, "alice", &mut bob, "bob")?;
        bob.send(&format!(
            "<iq type='get' to='alice@localhost/desk' id='client'>{QUERY}</iq>"
        ))?;
        alice.expect_xml(&format!("<iq xmlns='jabber:client' type='get' id='client' from='bob@localhost/desk' to='alice@localhost/desk'>{QUERY}</iq>"))?;
        alice.send("<iq type='result' to='bob@localhost/desk' id='client'><query xmlns='jabber:iq:version'><name>Desk client</name><version>9.9</version></query></iq>")?;
        bob.expect_xml("<iq xmlns='jabber:client' type='result' id='client' from='alice@localhost/desk' to='bob@localhost/desk'><query xmlns='jabber:iq:version'><name>Desk client</name><version>9.9</version></query></iq>")?;
        alice.close()?;
        bob.close()?;
    }
    Ok(())
}

#[test]
fn software_version_queries_leave_hosted_services_in_control() -> TestResult {
    for extensions in ["'version', 'test-service'", "'test-service'"] {
        let suite = C2sSuite::with_extensions(extensions)?;
        suite.create_account("alice", PASSWORD)?;
        let mut alice = suite.connect("alice", PASSWORD, "desk")?;
        alice.send(&format!("<iq type='get' to='echo.localhost' id='service-version'>{QUERY}</iq><iq type='get' to='echo.localhost' id='service-control'><query xmlns='urn:lonewolf:test:service'/></iq>"))?;
        alice.expect_xml("<iq xmlns='jabber:client' type='result' from='echo.localhost' to='alice@localhost/desk' id='service-control'><query xmlns='urn:lonewolf:test:service'><count>0</count></query></iq>")?;
        alice.send(&format!(
            "<iq type='set' to='echo.localhost' id='service-set'>{QUERY}</iq>"
        ))?;
        alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' from='echo.localhost' to='alice@localhost/desk' id='service-set'>{QUERY}<error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The request has an invalid structure or value. Check the request format.</text></error></iq>"))?;
        alice.close()?;
    }
    Ok(())
}
