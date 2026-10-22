// SPDX-License-Identifier: Apache-2.0

use crate::support::PASSWORD;

use std::time::{Duration, Instant};

use crate::support::{C2sSuite, Client, TestResult};

const NAMESPACE: &str = "urn:lonewolf:test:service";

#[test]
fn service_answers_iq_requests_addressed_to_its_domain() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-service'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='get' to='echo.localhost' id='service'><query xmlns='urn:lonewolf:test:service'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' from='echo.localhost' to='alice@localhost/desk' id='service'><query xmlns='urn:lonewolf:test:service'><count>0</count></query></iq>")?;
    alice.close()
}

#[test]
fn service_errors_become_error_replies() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-service'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='set' to='echo.localhost' id='service'><query xmlns='urn:lonewolf:test:service'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' from='echo.localhost' to='alice@localhost/desk' id='service'><query xmlns='urn:lonewolf:test:service'/><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The request has an invalid structure or value. Check the request format.</text></error></iq>")?;
    alice.close()
}

#[test]
fn service_messages_reach_the_sender_through_local_delivery() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-service'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send(
        "<message type='chat' to='room@echo.localhost' id='echo'><body>hello</body></message>",
    )?;
    alice.expect_xml("<message xmlns='jabber:client' type='chat' from='room@echo.localhost' to='alice@localhost/desk' id='echo'><body>hello</body></message>")?;
    alice.close()
}

#[test]
fn directed_presence_to_a_service_is_withdrawn_when_the_session_ends() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-service'")?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "phone")?;
    alice.send("<presence to='room@echo.localhost/a'/>")?;
    assert_eq!(joined(&mut alice)?, 1);
    assert_eq!(joined(&mut bob)?, 1);
    alice.close()?;
    wait_for_count(&mut bob, 0)?;
    bob.close()
}

#[test]
fn unavailable_presence_withdraws_service_presence() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-service'")?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "phone")?;
    alice.send("<presence to='room@echo.localhost/a'/>")?;
    assert_eq!(joined(&mut alice)?, 1);
    assert_eq!(joined(&mut bob)?, 1);
    alice.send("<presence type='unavailable'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost' type='unavailable'/>")?;
    wait_for_count(&mut bob, 0)?;
    alice.close()?;
    bob.close()
}

#[test]
fn service_domain_conflicting_with_a_host_prevents_startup() -> TestResult {
    let error = C2sSuite::with_extensions("'test-host-service'")
        .err()
        .ok_or("server started with a conflicting service domain")?;
    assert!(
        error.to_string().contains("conflicts with a served host"),
        "{error}"
    );
    Ok(())
}

#[test]
fn service_can_store_a_message_to_the_account_becoming_unavailable() -> TestResult {
    let suite = C2sSuite::with_extensions("'offline', 'test-service-offline-withdrawal'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<presence/>")?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>",
    )?;
    alice.send("<presence to='room@echo.localhost/a'/>")?;
    assert_eq!(joined(&mut alice)?, 1);
    alice.send("<presence type='unavailable'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost' type='unavailable'/>")?;
    suite.wait_for_log("test service withdrawal message stored")?;
    alice.send("<presence/>")?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>",
    )?;
    let message = alice.receive()?;
    message.assert_name("jabber:client", "message");
    assert_eq!(message.attribute("from"), Some("echo.localhost"));
    assert_eq!(message.child("jabber:client", "body")?.text, "withdrawn");
    alice.close()
}

#[test]
fn service_can_store_a_message_to_the_account_whose_session_ends() -> TestResult {
    let suite = C2sSuite::with_extensions("'offline', 'test-service-offline-withdrawal'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<presence/>")?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>",
    )?;
    alice.send("<presence to='room@echo.localhost/a'/>")?;
    assert_eq!(joined(&mut alice)?, 1);
    alice.close()?;
    suite.wait_for_log("test service withdrawal message stored")?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<presence/>")?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>",
    )?;
    let message = alice.receive()?;
    message.assert_name("jabber:client", "message");
    assert_eq!(message.attribute("from"), Some("echo.localhost"));
    assert_eq!(message.child("jabber:client", "body")?.text, "withdrawn");
    alice.close()
}

#[test]
fn pending_service_unavailable_survives_session_replacement() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-service-delayed-unavailable'")?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "phone")?;
    tag_session(&mut alice)?;
    alice.send("<presence to='bob@localhost/phone'/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/phone'/>",
    )?;
    alice.send("<presence to='room@echo.localhost/a'/>")?;
    assert_eq!(joined(&mut alice)?, 1);
    alice.send("<presence type='unavailable' to='room@echo.localhost/a'/>")?;
    suite.wait_for_log("test service presence waiting")?;
    bob.send(
        "<message type='chat' to='alice@localhost/desk'><body>check transport</body></message>",
    )?;
    alice.expect_xml("<message xmlns='jabber:client' type='chat' from='bob@localhost/phone' to='alice@localhost/desk'><body>check transport</body></message>")?;
    alice.reset()?;
    retire_session(&mut bob)?;
    let mut replacement = suite.connect("alice", PASSWORD, "desk")?;
    assert_eq!(joined(&mut bob)?, 1);
    release(&mut bob)?;
    suite.wait_for_log("test service withdrawal handled")?;
    wait_for_count(&mut bob, 0)?;
    replacement.close()?;
    bob.close()
}

#[test]
fn delayed_service_available_is_withdrawn_before_replacement_joins() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-service-delayed-available'")?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "phone")?;
    tag_session(&mut alice)?;
    alice.send("<presence to='bob@localhost/phone'/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/phone'/>",
    )?;
    alice.send("<presence to='room@echo.localhost/a'/>")?;
    suite.wait_for_log("test service presence waiting")?;
    bob.send(
        "<message type='chat' to='alice@localhost/desk'><body>check transport</body></message>",
    )?;
    alice.expect_xml("<message xmlns='jabber:client' type='chat' from='bob@localhost/phone' to='alice@localhost/desk'><body>check transport</body></message>")?;
    alice.reset()?;
    retire_session(&mut bob)?;
    let mut replacement = suite.connect("alice", PASSWORD, "desk")?;
    replacement.send("<presence to='room@echo.localhost/a'/>")?;
    assert_eq!(joined(&mut bob)?, 0);
    release(&mut bob)?;
    suite.wait_for_log("test service withdrawal handled")?;
    assert_eq!(joined(&mut replacement)?, 1);
    assert_eq!(joined(&mut bob)?, 1);
    replacement.close()?;
    wait_for_count(&mut bob, 0)?;
    bob.close()
}

fn tag_session(client: &mut Client) -> TestResult {
    client.send(
        "<iq type='get' id='tag-session'><tag-session xmlns='urn:lonewolf:test:service'/></iq>",
    )?;
    client.expect_xml(
        "<iq xmlns='jabber:client' type='result' id='tag-session' to='alice@localhost/desk'/>",
    )
}

fn retire_session(client: &mut Client) -> TestResult {
    client.send("<iq type='get' to='alice@localhost' id='retire-session'><retire-session xmlns='urn:lonewolf:test:service'/></iq>")?;
    let mut acknowledged = false;
    let mut withdrawn = false;
    for _ in 0..2 {
        let reply = client.receive().map_err(|error| {
            format!("retirement reply pending (acknowledged={acknowledged}, withdrawn={withdrawn}): {error}")
        })?;
        match (reply.namespace.as_str(), reply.name.as_str()) {
            ("jabber:client", "iq") => {
                assert!(!acknowledged, "duplicate retirement acknowledgement");
                reply.assert_xml("<iq xmlns='jabber:client' type='result' from='alice@localhost' to='bob@localhost/phone' id='retire-session'/>")?;
                acknowledged = true;
            }
            ("jabber:client", "presence") => {
                assert!(!withdrawn, "duplicate unavailable presence");
                reply.assert_xml("<presence xmlns='jabber:client' type='unavailable' from='alice@localhost/desk' to='bob@localhost/phone'/>")?;
                withdrawn = true;
            }
            _ => return Err("unexpected reply during session retirement".into()),
        }
    }
    assert!(acknowledged && withdrawn);
    Ok(())
}

fn release(client: &mut Client) -> TestResult {
    client.send("<iq type='get' to='echo.localhost' id='release'><release xmlns='urn:lonewolf:test:service'/></iq>")?;
    client.expect_xml("<iq xmlns='jabber:client' type='result' id='release' from='echo.localhost' to='bob@localhost/phone'/>")
}

fn joined(client: &mut Client) -> TestResult<usize> {
    client.send("<iq type='get' to='echo.localhost' id='count'><query xmlns='urn:lonewolf:test:service'/></iq>")?;
    let reply = client.receive()?;
    reply.assert_name("jabber:client", "iq");
    assert_eq!(reply.attribute("type"), Some("result"));
    assert_eq!(reply.attribute("from"), Some("echo.localhost"));
    Ok(reply
        .child(NAMESPACE, "query")?
        .child(NAMESPACE, "count")?
        .text
        .parse()?)
}

fn wait_for_count(client: &mut Client, expected: usize) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let actual = joined(client)?;
        if actual == expected {
            return Ok(());
        }
        assert!(
            Instant::now() < deadline,
            "service count stayed at {actual}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
