// SPDX-License-Identifier: Apache-2.0

use crate::support::component::{ComponentClient, NAMESPACE};
use crate::support::xml::Element;
use crate::support::{C2sSuite, TestResult};

const DOMAIN: &str = "muc.localhost";
const SECRET: &str = "component-test-secret-0001";
const CONFIG: &str = "[components.domains.'muc.localhost']\nsecret='component-test-secret-0001'";
const STANZA_ERRORS: &str = "urn:ietf:params:xml:ns:xmpp-stanzas";

pub(super) fn assert_counter(metrics: &str, sample: &str, expected: u64) -> TestResult {
    let value = metrics
        .lines()
        .find_map(|line| {
            line.strip_prefix(sample)
                .and_then(|value| value.strip_prefix(' '))
        })
        .unwrap_or("0")
        .parse::<u64>()?;
    assert_eq!(value, expected, "{sample}");
    Ok(())
}

fn rejected_stream(component: &mut ComponentClient, condition: &str) -> TestResult {
    component.expect_stream_error(condition)?;
    component.expect_footer()?;
    component.shutdown_write()?;
    component.expect_eof()
}

fn assert_error(
    stanza: &Element,
    kind: &str,
    id: &str,
    error_type: &str,
    condition: &str,
) -> TestResult {
    stanza.assert_name(NAMESPACE, kind);
    assert_eq!(stanza.attribute("id"), Some(id));
    assert_eq!(stanza.attribute("from"), Some("alice@localhost/desk"));
    assert_eq!(stanza.attribute("to"), Some("room@muc.localhost/member"));
    assert_eq!(stanza.attribute("type"), Some("error"));
    let error = stanza.child(NAMESPACE, "error")?;
    assert_eq!(error.attribute("type"), Some(error_type));
    error.child(STANZA_ERRORS, condition)?;
    Ok(())
}

#[test]
fn accepted_and_rejected_stanza_kinds_enforce_address_and_namespace_priority() -> TestResult {
    let mut suite = C2sSuite::with_components(&format!(
        "{CONFIG}\n[limits.components]\nconnection_attempts_per_ip={{per_second=100,burst=100}}"
    ))?;
    let mut counts = [0_u64; 3];
    for (kind, valid_type) in [
        ("message", "chat"),
        ("presence", "unavailable"),
        ("iq", "get"),
    ] {
        for stanza_type in [valid_type, "unknown"] {
            for (attributes, condition, outcome, index) in [
                (
                    "to='alice@localhost/desk'",
                    "improper-addressing",
                    "improper_addressing",
                    0,
                ),
                (
                    "from='room@muc.localhost/member'",
                    "improper-addressing",
                    "improper_addressing",
                    0,
                ),
                (
                    "from='not a jid@@' to='alice@localhost/desk'",
                    "improper-addressing",
                    "improper_addressing",
                    0,
                ),
                (
                    "from='room@other.localhost' to='not a jid@@'",
                    "improper-addressing",
                    "improper_addressing",
                    0,
                ),
                (
                    "from='room@other.localhost' to='alice@localhost/desk'",
                    "invalid-from",
                    "invalid_from",
                    1,
                ),
                (
                    "xmlns='jabber:client'",
                    "invalid-namespace",
                    "invalid_namespace",
                    2,
                ),
                (
                    "xmlns='urn:test:foreign' from='room@muc.localhost/member' to='alice@localhost/desk'",
                    "invalid-namespace",
                    "invalid_namespace",
                    2,
                ),
            ] {
                let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
                component.send(&format!(
                    "<{kind} type='{stanza_type}' id='invalid' {attributes}><payload xmlns='urn:test'/></{kind}>"
                ))?;
                rejected_stream(&mut component, condition)?;
                counts[index] += 1;
                suite.wait_for_metric(&format!(
                    "lonewolf_component_streams_closed_total{{outcome=\"{outcome}\"}} {}",
                    counts[index]
                ))?;
                suite.wait_for_metric("lonewolf_component_streams 0")?;
            }
        }
    }
    let metrics = suite.scrape_metrics()?;
    for kind in ["message", "presence", "iq"] {
        for family in ["received", "sent"] {
            assert_counter(
                &metrics,
                &format!("lonewolf_component_stanzas_{family}_total{{kind=\"{kind}\"}}"),
                0,
            )?;
        }
    }
    suite.stop()
}

#[test]
fn rejected_stanza_replies_keep_attachment_affinity_after_failed_authentication() -> TestResult {
    let mut suite = C2sSuite::with_components(&format!("{CONFIG}\nmax_connections=2"))?;
    let mut failed = ComponentClient::connect(suite.component_address(0)?)?;
    failed.open(DOMAIN, None)?;
    failed.send("<handshake>wrong</handshake>")?;
    rejected_stream(&mut failed, "not-authorized")?;
    let mut first = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    let mut second = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    for (component, id) in [(&mut first, "first"), (&mut second, "second")] {
        component.send(&format!(
            "<iq type='unknown' id='{id}' from='room@muc.localhost/member' to='alice@localhost/desk'><query xmlns='urn:test'/></iq>"
        ))?;
        assert_error(&component.receive()?, "iq", id, "modify", "bad-request")?;
    }
    suite.wait_for_metric("lonewolf_component_stanzas_received_total{kind=\"iq\"} 2")?;
    suite.wait_for_metric("lonewolf_component_stanzas_sent_total{kind=\"iq\"} 2")?;
    first.close()?;
    second.close()?;
    suite.wait_for_metric("lonewolf_component_streams 0")?;
    suite.wait_for_metric("lonewolf_component_streams_closed_total{outcome=\"stream_end\"} 2")?;
    suite.stop()
}

#[test]
fn missing_account_rejections_preserve_input_fifo_and_do_not_reply_to_non_requests() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    for index in 0..50 {
        let stanza_type = if index % 2 == 0 { "get" } else { "set" };
        component.send(&format!(
            "<iq type='{stanza_type}' id='ordered{index}' from='room@muc.localhost/member' to='alice@localhost/desk'><query xmlns='urn:test'/></iq>"
        ))?;
    }
    for index in 0..50 {
        let reply = component.receive()?;
        assert_error(
            &reply,
            "iq",
            &format!("ordered{index}"),
            "cancel",
            "service-unavailable",
        )?;
        reply.child("urn:test", "query")?;
    }
    for stanza_type in ["chat", "normal", "groupchat", "headline", ""] {
        let type_attribute = if stanza_type.is_empty() {
            String::new()
        } else {
            format!("type='{stanza_type}'")
        };
        component.send(&format!(
            "<message {type_attribute} id='message-{stanza_type}' from='room@muc.localhost/member' to='alice@localhost/desk'><body>preserve this body</body></message>"
        ))?;
        let reply = component.receive()?;
        assert_error(
            &reply,
            "message",
            &format!("message-{stanza_type}"),
            "cancel",
            "service-unavailable",
        )?;
        assert_eq!(reply.child(NAMESPACE, "body")?.text, "preserve this body");
    }
    for stanza in [
        "<message type='error' id='message-error' from='room@muc.localhost/member' to='alice@localhost/desk'/>",
        "<iq type='result' id='iq-result' from='room@muc.localhost/member' to='alice@localhost/desk'/>",
        "<iq type='error' id='iq-error' from='room@muc.localhost/member' to='alice@localhost/desk'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>",
        "<iq type='result' id='rejected-result' from='room@muc.localhost/member' to='alice@localhost/desk'><one xmlns='urn:test'/><two xmlns='urn:test'/></iq>",
    ] {
        component.send(stanza)?;
    }
    for stanza_type in [
        "",
        "unavailable",
        "probe",
        "subscribe",
        "subscribed",
        "unsubscribe",
        "unsubscribed",
        "error",
    ] {
        let type_attribute = if stanza_type.is_empty() {
            String::new()
        } else {
            format!("type='{stanza_type}'")
        };
        component.send(&format!(
            "<presence {type_attribute} from='room@muc.localhost/member' to='alice@localhost/desk'/>"
        ))?;
    }
    component.send("<iq type='get' id='barrier' from='room@muc.localhost/member' to='alice@localhost/desk'><query xmlns='urn:test'/></iq>")?;
    component.expect_xml("<presence xmlns='jabber:component:accept' type='unsubscribed' from='alice@localhost' to='room@muc.localhost/member'/>")?;
    assert_error(
        &component.receive()?,
        "iq",
        "barrier",
        "cancel",
        "service-unavailable",
    )?;
    component.close()?;
    suite.wait_for_metric("lonewolf_component_streams 0")?;
    let metrics = suite.scrape_metrics()?;
    for (kind, received, sent) in [("message", 6, 5), ("iq", 54, 51), ("presence", 8, 1)] {
        assert_counter(
            &metrics,
            &format!("lonewolf_component_stanzas_received_total{{kind=\"{kind}\"}}"),
            received,
        )?;
        assert_counter(
            &metrics,
            &format!("lonewolf_component_stanzas_sent_total{{kind=\"{kind}\"}}"),
            sent,
        )?;
    }
    suite.stop()
}

#[test]
fn transport_eof_aborts_without_xml_and_releases_the_component_attachment() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    component.shutdown_write()?;
    component.expect_eof()?;
    suite.wait_for_metric("lonewolf_component_streams 0")?;
    suite.wait_for_metric("lonewolf_component_connections 0")?;
    suite.wait_for_metric(
        "lonewolf_component_streams_closed_total{outcome=\"transport_error\"} 1",
    )?;
    let mut replacement = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    replacement.close()?;
    suite.wait_for_metric("lonewolf_component_streams 0")?;
    suite.wait_for_metric("lonewolf_component_streams_closed_total{outcome=\"stream_end\"} 1")?;
    let state = suite
        .stop_with_component_state()?
        .ok_or("missing final component state")?;
    assert_eq!(state.connections, 0);
    assert_eq!(state.streams, 0);
    assert_eq!(state.streams_closed_total, 2);
    assert_eq!(state.streams_closed_shutdown, 0);
    Ok(())
}
