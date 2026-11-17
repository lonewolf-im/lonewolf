// SPDX-License-Identifier: Apache-2.0

use crate::support::component::{ComponentClient, NAMESPACE};
use crate::support::xml::{Element, STREAM_NAMESPACE};
use crate::support::{ALTERNATE_PASSWORD, C2sSuite, PASSWORD, TestResult, barrier};

const DOMAIN: &str = "muc.localhost";
const SECRET: &str = "component-test-secret-0001";
const CONFIG: &str = "[components.domains.'muc.localhost']\nsecret='component-test-secret-0001'";

fn close_error(component: &mut ComponentClient, condition: &str) -> TestResult {
    component.expect_stream_error(condition)?;
    component.expect_footer()?;
    component.send("</stream:stream>")?;
    component.expect_eof()
}
fn metric(suite: &C2sSuite, family: &str, label: &str, value: u64) -> TestResult {
    suite.wait_for_metric(&format!("lonewolf_component_{family}{{{label}}} {value}"))?;
    Ok(())
}
fn query(component: &mut ComponentClient, id: &str) -> TestResult {
    component.send(&format!("<iq type='get' id='{id}' from='room@muc.localhost' to='alice@localhost/desk'><query xmlns='urn:test'/></iq>"))
}
fn assert_reply(reply: &Element, id: &str) -> TestResult {
    reply.assert_name(NAMESPACE, "iq");
    assert_eq!(reply.attribute("id"), Some(id));
    assert_eq!(reply.attribute("type"), Some("error"));
    assert_eq!(reply.attribute("from"), Some("alice@localhost/desk"));
    assert_eq!(reply.attribute("to"), Some("room@muc.localhost"));
    reply.child("urn:test", "query")?;
    reply
        .child(NAMESPACE, "error")?
        .child("urn:ietf:params:xml:ns:xmpp-stanzas", "service-unavailable")?;
    Ok(())
}

#[test]
fn client_messages_iqs_and_directed_presence_reach_component_with_original_content() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    alice.send("<message type='chat' to='room@muc.localhost' id='chat'><body>hello component</body></message>")?;
    component.expect_xml("<message xmlns='jabber:component:accept' type='chat' to='room@muc.localhost' from='alice@localhost/desk' id='chat'><body>hello component</body></message>")?;
    alice.send(
        "<iq type='get' to='room@muc.localhost' id='request'><query xmlns='urn:test'/></iq>",
    )?;
    component.expect_xml("<iq xmlns='jabber:component:accept' type='get' to='room@muc.localhost' from='alice@localhost/desk' id='request'><query xmlns='urn:test'/></iq>")?;
    alice.send("<presence to='room@muc.localhost/a'><status>ready</status></presence>")?;
    component.expect_xml("<presence xmlns='jabber:component:accept' to='room@muc.localhost/a' from='alice@localhost/desk'><status>ready</status></presence>")?;
    metric(&suite, "stanzas_sent_total", "kind=\"message\"", 1)?;
    metric(&suite, "stanzas_sent_total", "kind=\"iq\"", 1)?;
    alice.close()?;
    component.expect_xml("<presence xmlns='jabber:component:accept' type='unavailable' to='room@muc.localhost/a' from='alice@localhost/desk'/>")?;
    metric(&suite, "stanzas_sent_total", "kind=\"presence\"", 2)?;
    let bytes = suite.scrape_metrics()?;
    for family in [
        "lonewolf_component_sent_bytes_total ",
        "lonewolf_component_received_bytes_total ",
    ] {
        let value = bytes
            .lines()
            .find_map(|line| line.strip_prefix(family))
            .ok_or("missing socket byte counter")?
            .parse::<u64>()?;
        assert!(value > 0);
    }
    component.close()?;
    suite.stop()
}

#[test]
fn fifty_client_messages_preserve_fifo_and_unauthorized_iqs_return_to_component() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    for n in 0..50 {
        alice.send(&format!(
            "<message type='chat' to='room@muc.localhost' id='m{n}'><body>{n}</body></message>"
        ))?;
    }
    for n in 0..50 {
        let message = component.receive()?;
        message.assert_name(NAMESPACE, "message");
        assert_eq!(message.attribute("id"), Some(format!("m{n}").as_str()));
        assert_eq!(message.child(NAMESPACE, "body")?.text, n.to_string());
    }
    query(&mut component, "x")?;
    assert_reply(&component.receive()?, "x")?;
    metric(&suite, "stanzas_sent_total", "kind=\"message\"", 50)?;
    metric(&suite, "stanzas_received_total", "kind=\"iq\"", 1)?;
    component.close()?;
    alice.close()?;
    suite.stop()
}

#[test]
fn component_violations_keep_exact_conditions_and_close_metrics() -> TestResult {
    let mut suite = C2sSuite::with_components(&format!(
        "{CONFIG}\n[limits.components]\nmax_stanza_bytes=10000"
    ))?;
    let oversized = format!(
        "<message from='muc.localhost' to='localhost'><body>{}</body></message>",
        "x".repeat(10001)
    );
    for (index, (xml, condition, outcome)) in [
        (
            "<message from='room@other.localhost' to='alice@localhost/desk'/>",
            "invalid-from",
            "invalid_from",
        ),
        (
            "<message from='room@muc.localhost'/>",
            "improper-addressing",
            "improper_addressing",
        ),
        (
            "<message xmlns='jabber:client' from='room@muc.localhost' to='alice@localhost/desk'/>",
            "invalid-namespace",
            "invalid_namespace",
        ),
        (
            "<handshake/>",
            "unsupported-stanza-type",
            "unsupported_stanza_type",
        ),
        (oversized.as_str(), "policy-violation", "protocol_error"),
        ("<message></wrong>", "not-well-formed", "protocol_error"),
        (
            "<message from='room@muc.localhost' to='not a jid@@'/>",
            "improper-addressing",
            "improper_addressing",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
        component.send(xml)?;
        close_error(&mut component, condition)?;
        let count = if index == 5 || index == 6 { 2 } else { 1 };
        metric(
            &suite,
            "streams_closed_total",
            &format!("outcome=\"{outcome}\""),
            count,
        )?;
        suite.wait_for_metric("lonewolf_component_streams 0")?;
    }
    suite.stop()
}

#[test]
fn rejected_stanza_syntax_replies_stay_on_the_connection_without_error_loops() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    component.send(
        "<iq type='nonsense' id='bad' from='room@muc.localhost' to='alice@localhost/desk'/>",
    )?;
    let reply = component.receive()?;
    reply.assert_name(NAMESPACE, "iq");
    assert_eq!(reply.attribute("id"), Some("bad"));
    reply
        .child(NAMESPACE, "error")?
        .child("urn:ietf:params:xml:ns:xmpp-stanzas", "bad-request")?;
    component
        .send("<message type='error' from='room@muc.localhost' to='alice@localhost/desk'/>")?;
    query(&mut component, "barrier")?;
    assert_reply(&component.receive()?, "barrier")?;
    metric(&suite, "stanzas_received_total", "kind=\"iq\"", 2)?;
    component.close()?;
    suite.stop()
}

#[test]
fn peer_error_aborts_without_xml_and_footer_releases_service_routing() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    component.send(
        "<stream:error><conflict xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>",
    )?;
    component.expect_eof()?;
    metric(&suite, "streams_closed_total", "outcome=\"peer_error\"", 1)?;
    suite.wait_for_metric("lonewolf_component_streams 0")?;
    let mut replacement = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    replacement.close()?;
    suite.wait_for_metric("lonewolf_component_streams 0")?;
    alice.send("<iq type='get' to='muc.localhost' id='offline'><query xmlns='urn:test'/></iq>")?;
    let reply = alice.receive()?;
    reply.child("jabber:client", "error")?.child(
        "urn:ietf:params:xml:ns:xmpp-stanzas",
        "remote-server-timeout",
    )?;
    metric(&suite, "streams_closed_total", "outcome=\"stream_end\"", 1)?;
    alice.close()?;
    suite.stop()
}

#[test]
fn two_instances_keep_source_fifo_reply_affinity_and_independent_failure() -> TestResult {
    let mut suite = C2sSuite::with_components(&format!("{CONFIG}\nmax_connections=2"))?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", ALTERNATE_PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", ALTERNATE_PASSWORD, "desk")?;
    let mut failed = ComponentClient::connect(suite.component_address(0)?)?;
    failed.open(DOMAIN, None)?;
    failed.send("<handshake>wrong</handshake>")?;
    close_error(&mut failed, "not-authorized")?;
    let mut first = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    let mut second = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    for n in 0..20 {
        alice.send(&format!(
            "<message type='chat' to='room@muc.localhost' id='a{n}'><body>{n}</body></message>"
        ))?;
        bob.send(&format!(
            "<message type='chat' to='room@muc.localhost' id='b{n}'><body>{n}</body></message>"
        ))?;
    }
    barrier(&mut alice)?;
    barrier(&mut bob)?;
    query(&mut first, "first")?;
    query(&mut second, "second")?;
    let mut distribution = [Vec::new(), Vec::new()];
    for (index, (component, marker)) in [(&mut first, "first"), (&mut second, "second")]
        .into_iter()
        .enumerate()
    {
        loop {
            let stanza = component.receive()?;
            if stanza.name == "iq" {
                assert_reply(&stanza, marker)?;
                break;
            }
            stanza.assert_name(NAMESPACE, "message");
            distribution[index].push((
                stanza.attribute("from").ok_or("missing sender")?.to_owned(),
                stanza.attribute("id").ok_or("missing ID")?.to_owned(),
            ));
        }
    }
    for (sender, prefix) in [("alice@localhost/desk", "a"), ("bob@localhost/desk", "b")] {
        let by_connection: Vec<Vec<&str>> = distribution
            .iter()
            .map(|received| {
                received
                    .iter()
                    .filter(|(from, _)| from == sender)
                    .map(|(_, id)| id.as_str())
                    .collect()
            })
            .collect();
        assert_eq!(
            by_connection.iter().filter(|ids| !ids.is_empty()).count(),
            1
        );
        let actual = by_connection
            .iter()
            .find(|ids| !ids.is_empty())
            .ok_or("sender not delivered")?;
        let expected: Vec<String> = (0..20).map(|n| format!("{prefix}{n}")).collect();
        assert_eq!(
            *actual,
            expected.iter().map(String::as_str).collect::<Vec<_>>()
        );
    }
    second.send("<message from='other.localhost' to='localhost'/>")?;
    close_error(&mut second, "invalid-from")?;
    suite.wait_for_metric("lonewolf_component_streams 1")?;
    alice.send("<message type='chat' to='room@muc.localhost' id='survivor'><body>still connected</body></message>")?;
    assert_eq!(first.receive()?.attribute("id"), Some("survivor"));
    metric(&suite, "stanzas_sent_total", "kind=\"message\"", 41)?;
    metric(&suite, "stanzas_received_total", "kind=\"iq\"", 2)?;
    first.close()?;
    alice.close()?;
    bob.close()?;
    suite.stop()
}

fn fill_queue(suite: &C2sSuite, alice: &mut crate::support::Client) -> TestResult<usize> {
    let payload_len = lonewolf_core::config::Config::default()
        .limits
        .components
        .max_stanza_bytes
        .get()
        / 2;
    let body = "x".repeat(payload_len);
    for n in 0..256 {
        alice.send(&format!("<message type='chat' to='room@muc.localhost' id='load{n}'><body>{body}</body></message>"))?;
        alice.send("<iq type='get' id='admitted'><query xmlns='urn:test:barrier'/></iq>")?;
        let response = alice.receive()?;
        if response.name == "message" {
            assert_eq!(response.attribute("id"), Some(format!("load{n}").as_str()));
            response
                .child("jabber:client", "error")?
                .child("urn:ietf:params:xml:ns:xmpp-stanzas", "resource-constraint")?;
            let barrier = alice.receive()?;
            assert_eq!(barrier.attribute("id"), Some("admitted"));
            metric(
                suite,
                "admission_rejections_total",
                "reason=\"queue_full\"",
                1,
            )?;
            return Ok(n + 1);
        }
        response.assert_name("jabber:client", "iq");
        assert_eq!(response.attribute("id"), Some("admitted"));
    }
    Err("component socket buffers did not fill within the payload bound".into())
}

#[test]
fn bounded_connection_queue_rejects_pressure_then_closes_at_a_stanza_boundary() -> TestResult {
    let mut suite = C2sSuite::with_components_limits(
        &format!("{CONFIG}\n[limits.components]\nmax_queued_stanzas=4"),
        "max_stanza_bytes=524288\nincoming_xml_per_connection={bytes_per_second=67108864,burst_bytes=67108864}\nincoming_stanzas_per_connection={per_second=2000,burst=2000}",
    )?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    let _sent = fill_queue(&suite, &mut alice)?;
    component.send("</stream:stream>")?;
    let mut received = 0;
    while let Some(stanza) = component.receive_or_footer()? {
        stanza.assert_name(NAMESPACE, "message");
        assert_eq!(
            stanza.attribute("id"),
            Some(format!("load{received}").as_str())
        );
        received += 1;
    }
    assert!(received > 0);
    component.shutdown_write()?;
    component.expect_eof()?;
    suite.wait_for_metric("lonewolf_component_streams 0")?;
    alice.close()?;
    suite.stop()
}

#[test]
fn no_progress_timeout_aborts_a_component_that_stops_reading_without_closing_xml() -> TestResult {
    let mut suite = C2sSuite::with_components_limits(
        &format!(
            "{CONFIG}\n[limits.components]\nmax_queued_stanzas=4\nstalled_write_timeout_secs=1"
        ),
        "max_stanza_bytes=524288\nincoming_xml_per_connection={bytes_per_second=67108864,burst_bytes=67108864}\nincoming_stanzas_per_connection={per_second=2000,burst=2000}",
    )?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    let _sent = fill_queue(&suite, &mut alice)?;
    metric(
        &suite,
        "streams_closed_total",
        "outcome=\"stalled_write\"",
        1,
    )?;
    let bytes = component.drain_to_eof()?;
    assert!(!bytes.is_empty());
    assert!(
        !bytes
            .windows(b"</stream:stream>".len())
            .any(|v| v == b"</stream:stream>")
    );
    assert!(
        !bytes
            .windows(b"<stream:error".len())
            .any(|v| v == b"<stream:error")
    );
    suite.wait_for_metric("lonewolf_component_connections 0")?;
    alice.close()?;
    suite.stop()
}

#[test]
fn shutdown_during_delivery_keeps_whole_stanzas_before_shutdown_error() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    for n in 0..50 {
        alice.send(&format!(
            "<message type='chat' to='room@muc.localhost' id='m{n}'><body>{}</body></message>",
            "x".repeat(4096)
        ))?;
    }
    barrier(&mut alice)?;
    std::thread::scope(|scope| -> TestResult {
        let receiving = scope.spawn(move || -> Result<(), String> {
            let mut read = || -> TestResult {
                let mut n = 0;
                loop {
                    let stanza = component.receive()?;
                    if stanza.namespace == STREAM_NAMESPACE {
                        stanza.child("urn:ietf:params:xml:ns:xmpp-streams", "system-shutdown")?;
                        break;
                    }
                    stanza.assert_name(NAMESPACE, "message");
                    assert_eq!(stanza.attribute("id"), Some(format!("m{n}").as_str()));
                    assert_eq!(stanza.child(NAMESPACE, "body")?.text.len(), 4096);
                    n += 1;
                }
                component.expect_footer()?;
                component.send("</stream:stream>")?;
                component.expect_eof()
            };
            read().map_err(|e| e.to_string())
        });
        let stopped = suite
            .stop_with_component_state()?
            .ok_or("missing final component state")?;
        receiving
            .join()
            .map_err(|_| "component receiver panicked")?
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        assert_eq!(stopped.connections, 0);
        assert_eq!(stopped.streams, 0);
        assert_eq!(stopped.authentication_total, 1);
        assert_eq!(stopped.streams_closed_shutdown, 1);
        assert_eq!(stopped.streams_closed_total, 1);
        Ok(())
    })
}
