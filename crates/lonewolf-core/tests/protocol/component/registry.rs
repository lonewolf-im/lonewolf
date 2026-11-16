// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::os::unix::fs::PermissionsExt;

use lonewolf_core::RunError;

use crate::support::{C2sSuite, PASSWORD, TestResult};

const DOMAIN: &str = "[components.domains.'muc.localhost']\nsecret_file='component-secret'";

fn secret(directory: &std::path::Path) -> TestResult {
    fs::write(
        directory.join("component-secret"),
        "component-test-secret-0001\n",
    )?;
    fs::set_permissions(
        directory.join("component-secret"),
        fs::Permissions::from_mode(0o600),
    )?;
    Ok(())
}

#[test]
fn disconnected_component_iqs_and_messages_return_timeout_errors() -> TestResult {
    let mut suite = C2sSuite::with_components_and_setup(DOMAIN, "", secret)?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='get' to='muc.localhost' id='q'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' from='muc.localhost' to='alice@localhost/desk' id='q'><query xmlns='http://jabber.org/protocol/disco#info'/><error type='wait'><remote-server-timeout xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The service at this domain is not connected. Try again later.</text></error></iq>")?;
    suite.wait_for_metric(
        "lonewolf_component_admission_rejections_total{reason=\"not_connected\"} 1",
    )?;
    alice.send(
        "<message type='chat' to='room@muc.localhost' id='chat'><body>synthetic</body></message>",
    )?;
    alice.expect_xml("<message xmlns='jabber:client' type='error' from='room@muc.localhost' to='alice@localhost/desk' id='chat'><body>synthetic</body><error type='wait'><remote-server-timeout xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The service at this domain is not connected. Try again later.</text></error></message>")?;
    suite.wait_for_metric(
        "lonewolf_component_admission_rejections_total{reason=\"not_connected\"} 2",
    )?;
    alice.close()?;
    suite.stop()
}

#[test]
fn nonbounceable_stanzas_to_a_disconnected_component_are_silent() -> TestResult {
    let mut suite = C2sSuite::with_components_and_setup(DOMAIN, "", secret)?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<presence to='room@muc.localhost/a'/><iq type='result' to='muc.localhost' id='ignored'/><message type='error' to='muc.localhost'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message><iq type='get' to='localhost' id='barrier'><ping xmlns='urn:xmpp:ping'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' from='localhost' to='alice@localhost/desk' id='barrier'/>")?;
    alice.close()?;
    suite.stop()
}

#[test]
fn component_discovery_follows_the_discoverable_setting() -> TestResult {
    for discoverable in [true, false] {
        let mut suite = C2sSuite::with_components_and_setup(
            &format!("{DOMAIN}\ndiscoverable={discoverable}"),
            "",
            secret,
        )?;
        suite.create_account("alice", PASSWORD)?;
        let mut alice = suite.connect("alice", PASSWORD, "desk")?;
        alice.send("<iq type='get' to='localhost' id='items'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>")?;
        if discoverable {
            alice.expect_xml("<iq xmlns='jabber:client' type='result' id='items' from='localhost' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#items'><item jid='muc.localhost'/></query></iq>")?;
        } else {
            alice.expect_xml("<iq xmlns='jabber:client' type='result' id='items' from='localhost' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>")?;
        }
        alice.close()?;
        suite.stop()?;
    }
    Ok(())
}

#[test]
fn short_component_secret_files_fail_startup_with_a_typed_domain_error() -> TestResult {
    let error = C2sSuite::with_components_and_setup(DOMAIN, "", |directory| {
        fs::write(directory.join("component-secret"), "123456789012345")?;
        Ok(())
    })
    .err()
    .ok_or("started with a short secret")?;
    let error = error
        .downcast::<RunError>()
        .map_err(|_| "missing typed startup failure")?;
    assert!(error.to_string().contains("muc.localhost"));
    match *error {
        RunError::ComponentSecret { domain, source } => {
            assert_eq!(domain, "muc.localhost");
            assert_eq!(source.kind(), std::io::ErrorKind::InvalidData);
            assert_eq!(
                source.to_string(),
                "component secret must be 16 to 1024 bytes"
            );
        }
        _ => return Err("wrong startup failure".into()),
    }
    Ok(())
}

#[test]
fn component_domains_cannot_replace_an_extension_service() -> TestResult {
    let error = C2sSuite::with_components_and_setup(
        "[components.domains.'echo.localhost']\nsecret_file='component-secret'",
        "[hosts.localhost]\nextensions=['test-service']",
        secret,
    )
    .err()
    .ok_or("started with a service collision")?;
    let error = error
        .downcast::<RunError>()
        .map_err(|_| "missing typed startup failure")?;
    assert_eq!(
        error.to_string(),
        "service domain \"echo.localhost\" conflicts with a served host or another service"
    );
    assert!(matches!(*error, RunError::ServiceDomain { ref domain } if domain == "echo.localhost"));
    Ok(())
}
