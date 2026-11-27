// SPDX-License-Identifier: Apache-2.0

use std::net::Ipv4Addr;

use time::{Duration, OffsetDateTime};

use crate::support::component::{ComponentClient, NAMESPACE};
use crate::support::federation::{
    FederatedPair, HostRevocation, PairOptions,
    crl_server::{CrlResponse, CrlServer},
};
use crate::support::{C2sSuite, PASSWORD, TestResult};

const DOMAIN: &str = "muc.a.test";
const ROOM: &str = "room@muc.a.test";
const BOB: &str = "bob@b.test/phone";
const SECRET: &str = "component-federation-secret-0001";
const ERRORS: &str = "urn:ietf:params:xml:ns:xmpp-stanzas";
const NOT_CONNECTED: &str = "The service at this domain is not connected. Try again later.";
const RESOURCE_LIMIT: &str = "The server cannot complete this request within its resource limits.";
const BOUNCES: &str = "lonewolf_component_bounces_total";
const QUEUE_FULL: &str = "lonewolf_component_admission_rejections_total{reason=\"queue_full\"}";
const NOT_CONNECTED_COUNT: &str =
    "lonewolf_component_admission_rejections_total{reason=\"not_connected\"}";
const HIGH_INPUT_RATES: &str = "incoming_stanzas_per_connection={per_second=2000,burst=2000}\nincoming_xml_per_connection={bytes_per_second=67108864,burst_bytes=134217728}";

fn extensions(write_probe: bool) -> String {
    let mut names = lonewolf_core::config::HostConfig::default().extensions;
    if write_probe {
        names.push("test-component-write-probe".into());
    }
    names
        .iter()
        .map(|name| format!("{name:?}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn options(covered: bool) -> PairOptions {
    PairOptions {
        a_certificate_names: if covered {
            vec![DOMAIN.into()]
        } else {
            Vec::new()
        },
        a_extensions: extensions(false),
        b_extensions: extensions(false),
        a_bidirectional: Some(false),
        b_bidirectional: Some(false),
        a_extra_toml: format!(
            "[[components.listeners]]\naddress='127.0.0.1:0'\n[components.domains.'{DOMAIN}']\nsecret='{SECRET}'"
        ),
        ..PairOptions::default()
    }
}

fn start(options: PairOptions) -> TestResult<FederatedPair> {
    let pair = FederatedPair::start("a.test", "b.test", options)?;
    let address = pair
        .a
        .s2s
        .as_ref()
        .and_then(|addresses| addresses.first())
        .ok_or("A has no S2S listener")?;
    pair.dns
        .srv(DOMAIN, &[(0, 0, address.port(), "component.a.test")]);
    pair.dns.a("component.a.test", Ipv4Addr::LOCALHOST);
    pair.a.create_account("alice", PASSWORD)?;
    pair.b.create_account("bob", PASSWORD)?;
    Ok(pair)
}

fn counter(metrics: &str, sample: &str) -> u64 {
    metrics
        .lines()
        .find_map(|line| {
            line.strip_prefix(sample)
                .and_then(|tail| tail.strip_prefix(' '))
                .map(|value| {
                    value
                        .parse::<u64>()
                        .unwrap_or_else(|error| panic!("{sample}: {error}"))
                })
        })
        .unwrap_or(0)
}

fn family_total(metrics: &str, family: &str) -> u64 {
    metrics
        .lines()
        .filter(|line| line.starts_with(family))
        .map(|line| {
            line.rsplit_once(' ')
                .and_then(|(_, value)| value.parse::<u64>().ok())
                .unwrap_or_else(|| panic!("invalid counter sample: {line}"))
        })
        .sum()
}

fn delta(suite: &C2sSuite, before: &str, name: &str, expected: u64) -> TestResult {
    let target = counter(before, name) + expected;
    suite.wait_for_metrics(name, |metrics| counter(metrics, name) == target)?;
    assert_eq!(counter(&suite.scrape_metrics()?, name), target, "{name}");
    Ok(())
}

fn traffic(
    suite: &C2sSuite,
    before: &str,
    transport: &str,
    direction: &str,
    kind: &str,
    count: u64,
) -> TestResult {
    delta(
        suite,
        before,
        &format!("lonewolf_{transport}_stanzas_{direction}_total{{kind=\"{kind}\"}}"),
        count,
    )
}

fn error_xml(
    kind: &str,
    namespace: &str,
    id: &str,
    (from, to): (&str, &str),
    payload: &str,
    condition: &str,
    text: &str,
) -> String {
    let error_type = if condition == "remote-server-not-found" {
        "cancel"
    } else {
        "wait"
    };
    format!(
        "<{kind} xml:lang='en' xmlns='{namespace}' type='error' from='{from}' to='{to}' id='{id}'>{payload}<error type='{error_type}'><{condition} xmlns='{ERRORS}'/><text xmlns='{ERRORS}' xml:lang='en'>{text}</text></error></{kind}>"
    )
}

fn chat_round_trip(crl_urls: bool) -> TestResult {
    let mut http = if crl_urls {
        Some(CrlServer::start()?)
    } else {
        None
    };
    let mut options = options(true);
    if let Some(http) = &http {
        options.a_revocation = HostRevocation {
            crl_url: Some(http.url("a.crl")),
            ..Default::default()
        };
        options.b_revocation = HostRevocation {
            crl_url: Some(http.url("b.crl")),
            ..Default::default()
        };
    }
    let mut pair = start(options)?;
    if let Some(http) = &mut http {
        let now = OffsetDateTime::now_utc();
        for path in ["a.crl", "b.crl"] {
            http.serve(
                path,
                CrlResponse::Body(pair.ca.crl(
                    &[],
                    now - Duration::minutes(1),
                    now + Duration::days(1),
                    1,
                )?),
            );
        }
    }
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    let mut component = ComponentClient::authenticated(&pair.a, DOMAIN, SECRET)?;
    let a_before = pair.a.scrape_metrics()?;
    let b_before = pair.b.scrape_metrics()?;

    bob.send("<message xml:lang='en' type='chat' to='room@muc.a.test' id='chat-in'><body>remote hello</body><extra xmlns='urn:test:component' value='kept'/></message>")?;
    component.expect_xml(&format!("<message xml:lang='en' xmlns='{NAMESPACE}' type='chat' from='{BOB}' to='{ROOM}' id='chat-in'><body>remote hello</body><extra xmlns='urn:test:component' value='kept'/></message>"))?;
    component.send(&format!("<message xml:lang='en' type='chat' from='{ROOM}/nick' to='{BOB}' id='chat-out'><body>component reply</body></message>"))?;
    bob.expect_xml(&format!("<message xml:lang='en' xmlns='jabber:client' type='chat' from='{ROOM}/nick' to='{BOB}' id='chat-out'><body>component reply</body></message>"))?;

    for (transport, direction) in [
        ("s2s", "received"),
        ("component", "sent"),
        ("component", "received"),
        ("s2s", "sent"),
    ] {
        traffic(&pair.a, &a_before, transport, direction, "message", 1)?;
    }
    traffic(&pair.b, &b_before, "s2s", "sent", "message", 1)?;
    traffic(&pair.b, &b_before, "s2s", "received", "message", 1)?;
    if let Some(http) = &http {
        for (suite, before) in [(&pair.a, &a_before), (&pair.b, &b_before)] {
            delta(
                suite,
                before,
                "lonewolf_s2s_crl_fetches_total{outcome=\"success\"}",
                1,
            )?;
        }
        assert_eq!(http.requests("a.crl"), 1);
        assert_eq!(http.requests("b.crl"), 1);
    }
    component.close()?;
    bob.close()?;
    pair.stop()
}

#[test]
fn covered_component_exchanges_chat_with_a_remote_full_jid() -> TestResult {
    chat_round_trip(false)
}

#[test]
fn covered_component_exchanges_chat_with_crl_url_certificates() -> TestResult {
    chat_round_trip(true)
}

#[test]
fn remote_disco_iq_result_returns_from_the_component_domain() -> TestResult {
    let mut pair = start(options(true))?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    let mut component = ComponentClient::authenticated(&pair.a, DOMAIN, SECRET)?;
    let before = pair.a.scrape_metrics()?;
    bob.send("<iq xml:lang='en' type='get' to='muc.a.test' id='disco'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")?;
    component.expect_xml(&format!("<iq xml:lang='en' xmlns='{NAMESPACE}' type='get' from='{BOB}' to='{DOMAIN}' id='disco'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>"))?;
    let payload = "<query xmlns='http://jabber.org/protocol/disco#info'><identity category='conference' type='text' name='Test room'/><feature var='http://jabber.org/protocol/muc'/></query>";
    component.send(&format!(
        "<iq xml:lang='en' type='result' from='{DOMAIN}' to='{BOB}' id='disco'>{payload}</iq>"
    ))?;
    bob.expect_xml(&format!("<iq xml:lang='en' xmlns='jabber:client' type='result' from='{DOMAIN}' to='{BOB}' id='disco'>{payload}</iq>"))?;
    for (transport, direction) in [
        ("s2s", "received"),
        ("component", "sent"),
        ("component", "received"),
        ("s2s", "sent"),
    ] {
        traffic(&pair.a, &before, transport, direction, "iq", 1)?;
    }
    component.close()?;
    bob.close()?;
    pair.stop()
}

#[test]
fn remote_directed_presence_is_withdrawn_from_the_component_on_logout() -> TestResult {
    let mut pair = start(options(true))?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    let mut component = ComponentClient::authenticated(&pair.a, DOMAIN, SECRET)?;
    bob.send("<presence xml:lang='en'/>")?;
    bob.expect_xml(&format!(
        "<presence xml:lang='en' xmlns='jabber:client' from='{BOB}' to='bob@b.test'/>"
    ))?;
    let before = pair.a.scrape_metrics()?;
    bob.send("<presence xml:lang='en' to='room@muc.a.test/bob'><show>chat</show><status>room participant</status></presence>")?;
    component.expect_xml(&format!("<presence xml:lang='en' xmlns='{NAMESPACE}' from='{BOB}' to='{ROOM}/bob'><show>chat</show><status>room participant</status></presence>"))?;
    bob.close()?;
    component.expect_xml(&format!(
        "<presence xml:lang='en' xmlns='{NAMESPACE}' type='unavailable' from='{BOB}' to='{ROOM}/bob'/>"
    ))?;
    traffic(&pair.a, &before, "s2s", "received", "presence", 2)?;
    traffic(&pair.a, &before, "component", "sent", "presence", 2)?;
    component.close()?;
    pair.stop()
}

#[test]
fn component_groupchat_reaches_local_and_remote_full_jids() -> TestResult {
    let mut pair = start(options(true))?;
    let mut alice = pair.a.connect("alice", PASSWORD, "desk")?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    let mut component = ComponentClient::authenticated(&pair.a, DOMAIN, SECRET)?;
    let a_before = pair.a.scrape_metrics()?;
    let b_before = pair.b.scrape_metrics()?;
    for (to, client) in [(BOB, &mut bob), ("alice@a.test/desk", &mut alice)] {
        component.send(&format!("<message xml:lang='en' type='groupchat' from='{ROOM}/nick' to='{to}' id='groupchat'><body>room announcement</body></message>"))?;
        client.expect_xml(&format!("<message xml:lang='en' xmlns='jabber:client' type='groupchat' from='{ROOM}/nick' to='{to}' id='groupchat'><body>room announcement</body></message>"))?;
    }
    traffic(&pair.a, &a_before, "component", "received", "message", 2)?;
    traffic(&pair.a, &a_before, "s2s", "sent", "message", 1)?;
    traffic(&pair.b, &b_before, "s2s", "received", "message", 1)?;
    component.close()?;
    alice.close()?;
    bob.close()?;
    pair.stop()
}

#[test]
fn disconnected_component_rejects_new_remote_iq_without_a_queued_bounce() -> TestResult {
    let mut pair = start(options(true))?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    let mut component = ComponentClient::authenticated(&pair.a, DOMAIN, SECRET)?;
    component.close()?;
    pair.a.wait_for_metric("lonewolf_component_connections 0")?;
    pair.a.wait_for_metric("lonewolf_component_streams 0")?;
    let before = pair.a.scrape_metrics()?;
    let payload = "<query xmlns='http://jabber.org/protocol/disco#info'/>";
    bob.send(&format!(
        "<iq xml:lang='en' type='get' to='{DOMAIN}' id='offline'>{payload}</iq>"
    ))?;
    bob.expect_xml(&error_xml(
        "iq",
        "jabber:client",
        "offline",
        (DOMAIN, BOB),
        payload,
        "remote-server-timeout",
        NOT_CONNECTED,
    ))?;
    delta(&pair.a, &before, NOT_CONNECTED_COUNT, 1)?;
    delta(&pair.a, &before, BOUNCES, 0)?;
    traffic(&pair.a, &before, "s2s", "received", "iq", 1)?;
    traffic(&pair.a, &before, "s2s", "sent", "iq", 1)?;
    bob.close()?;
    pair.stop()
}

#[test]
fn uncovered_component_domain_fails_starttls_negotiation_and_outbound_routing() -> TestResult {
    let mut pair = start(options(false))?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    let mut component = ComponentClient::authenticated(&pair.a, DOMAIN, SECRET)?;
    let a_before = pair.a.scrape_metrics()?;
    let b_before = pair.b.scrape_metrics()?;
    let payload = "<body>uncovered domain</body>";
    bob.send(&format!(
        "<message xml:lang='en' type='chat' to='{ROOM}' id='uncovered-in'>{payload}</message>"
    ))?;
    bob.expect_xml(&error_xml(
        "message",
        "jabber:client",
        "uncovered-in",
        (ROOM, BOB),
        payload,
        "remote-server-timeout",
        "The server could not reach the remote domain in time.",
    ))?;
    delta(
        &pair.a,
        &a_before,
        "lonewolf_s2s_authentications_total{direction=\"inbound\",outcome=\"host_unknown\"}",
        1,
    )?;
    delta(
        &pair.b,
        &b_before,
        "lonewolf_s2s_bounces_total{condition=\"remote_server_timeout\"}",
        1,
    )?;
    traffic(&pair.a, &a_before, "s2s", "received", "message", 0)?;
    component.send(&format!("<message xml:lang='en' type='chat' from='{ROOM}/nick' to='bob@b.test' id='uncovered-out'>{payload}</message>"))?;
    component.expect_xml(&error_xml(
        "message",
        NAMESPACE,
        "uncovered-out",
        ("bob@b.test", &format!("{ROOM}/nick")),
        payload,
        "remote-server-not-found",
        "The server cannot deliver this request to a remote domain.",
    ))?;
    traffic(&pair.a, &a_before, "component", "received", "message", 1)?;
    traffic(&pair.a, &a_before, "component", "sent", "message", 1)?;
    delta(&pair.a, &a_before, BOUNCES, 0)?;
    component.close()?;
    bob.close()?;
    pair.stop()
}

#[test]
fn reset_returns_exactly_four_queued_remote_messages_without_replaying_the_prefix_or_active_write()
-> TestResult {
    const QUEUE_BYTES: usize = 229376;
    let mut options = options(true);
    options.a_extensions = extensions(true);
    options.a_extra_toml.push_str(&format!(
        "\n[limits.components]\nmax_queued_stanzas=4\nmax_queued_bytes={QUEUE_BYTES}"
    ));
    options.b_extra_toml = format!("[limits.c2s.profiles.default]\n{HIGH_INPUT_RATES}");
    options.limits = HIGH_INPUT_RATES.into();
    let mut pair = start(options)?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    let mut control = pair.a.connect("alice", PASSWORD, "control")?;
    let (mut component, probe) =
        ComponentClient::authenticated_with_write_probe(&pair.a, DOMAIN, SECRET, &mut control)?;
    let data_payload = format!(
        "<body>{}</body><extra xmlns='urn:test:remote-loss' marker='kept'><first>one</first><second>two</second></extra>",
        "d".repeat(49152)
    );
    let probe_payload = format!(
        "<query xmlns='urn:test:admission'>{}</query>",
        "p".repeat(245760)
    );
    let data = |id: &str| {
        format!(
            "<message xml:lang='en' xmlns='jabber:client' type='chat' from='{BOB}' to='{ROOM}' id='{id}'>{data_payload}</message>"
        )
    };
    let admission_probe = |id: &str| {
        format!(
            "<iq xml:lang='en' xmlns='jabber:client' type='get' from='{BOB}' to='{DOMAIN}' id='{id}'>{probe_payload}</iq>"
        )
    };
    let probe_reply = |id: &str| {
        error_xml(
            "iq",
            "jabber:client",
            id,
            (DOMAIN, BOB),
            &probe_payload,
            "resource-constraint",
            RESOURCE_LIMIT,
        )
    };
    assert!(4 * data("tail-4").len() < QUEUE_BYTES);
    assert!(admission_probe("probe-overflow").len() > QUEUE_BYTES);
    for xml in [
        admission_probe("probe-overflow"),
        probe_reply("probe-overflow"),
    ] {
        assert!(xml.len() < 262144);
        assert!(xml.len() < 524288);
    }
    let a_before = pair.a.scrape_metrics()?;
    bob.send(&data("prefix"))?;
    component.expect_xml(&format!("<message xml:lang='en' xmlns='{NAMESPACE}' type='chat' from='{BOB}' to='{ROOM}' id='prefix'>{data_payload}</message>"))?;
    traffic(&pair.a, &a_before, "component", "sent", "message", 1)?;
    probe.hold_after_bytes(&mut control, 64)?;
    bob.send(&data("active"))?;
    bob.send(&admission_probe("probe-active"))?;
    bob.expect_xml(&probe_reply("probe-active"))?;
    probe.wait_held(&mut control)?;
    let tail = ["tail-1", "tail-2", "tail-3", "tail-4"];
    for id in tail {
        bob.send(&data(id))?;
        let probe_id = format!("probe-{id}");
        bob.send(&admission_probe(&probe_id))?;
        bob.expect_xml(&probe_reply(&probe_id))?;
    }
    bob.send(&data("overflow"))?;
    bob.send(&admission_probe("probe-overflow"))?;
    bob.expect_xml(&error_xml(
        "message",
        "jabber:client",
        "overflow",
        (ROOM, BOB),
        &data_payload,
        "resource-constraint",
        RESOURCE_LIMIT,
    ))?;
    bob.expect_xml(&probe_reply("probe-overflow"))?;
    delta(&pair.a, &a_before, QUEUE_FULL, 7)?;
    delta(&pair.a, &a_before, BOUNCES, 0)?;
    traffic(&pair.a, &a_before, "s2s", "received", "message", 7)?;
    traffic(&pair.a, &a_before, "s2s", "received", "iq", 6)?;
    traffic(&pair.a, &a_before, "component", "sent", "message", 1)?;
    let a_return = pair.a.scrape_metrics()?;
    let b_return = pair.b.scrape_metrics()?;

    component.reset()?;
    pair.a.wait_for_metric("lonewolf_component_connections 0")?;
    pair.a.wait_for_metric("lonewolf_component_streams 0")?;
    probe.remove(&mut control)?;
    for id in tail {
        bob.expect_xml(&error_xml(
            "message",
            "jabber:client",
            id,
            (ROOM, BOB),
            &data_payload,
            "remote-server-timeout",
            NOT_CONNECTED,
        ))?;
    }
    delta(&pair.a, &a_before, BOUNCES, 4)?;
    let after = pair.a.scrape_metrics()?;
    let n = 1 + 1 + tail.len() as u64;
    let w = counter(
        &after,
        "lonewolf_component_stanzas_sent_total{kind=\"message\"}",
    ) - counter(
        &a_before,
        "lonewolf_component_stanzas_sent_total{kind=\"message\"}",
    );
    let r = counter(&after, BOUNCES) - counter(&a_before, BOUNCES);
    assert_eq!((n, w, r), (6, 1, 4));
    assert!(r > 0);
    assert!(w + r <= n);
    assert!(n - w - r <= 1);
    for name in [
        "lonewolf_component_moved_stanzas_total",
        "lonewolf_component_dropped_stanzas_total{reason=\"not_bounceable\"}",
        "lonewolf_component_dropped_stanzas_total{reason=\"shutdown\"}",
    ] {
        delta(&pair.a, &a_before, name, 0)?;
    }
    for name in [
        "lonewolf_component_queued_stanzas",
        "lonewolf_component_queued_bytes",
    ] {
        assert_eq!(counter(&after, name), 0, "{name}");
    }
    traffic(&pair.a, &a_return, "s2s", "sent", "message", 4)?;
    traffic(&pair.b, &b_return, "s2s", "received", "message", 4)?;
    for (suite, before) in [(&pair.a, &a_return), (&pair.b, &b_return)] {
        assert_eq!(
            family_total(&suite.scrape_metrics()?, "lonewolf_s2s_bounces_total{"),
            family_total(before, "lonewolf_s2s_bounces_total{")
        );
    }
    let final_payload = "<query xmlns='http://jabber.org/protocol/disco#info'/>";
    bob.send(&format!(
        "<iq xml:lang='en' type='get' to='{DOMAIN}' id='after-recovery'>{final_payload}</iq>"
    ))?;
    bob.expect_xml(&error_xml(
        "iq",
        "jabber:client",
        "after-recovery",
        (DOMAIN, BOB),
        final_payload,
        "remote-server-timeout",
        NOT_CONNECTED,
    ))?;
    delta(&pair.a, &a_before, NOT_CONNECTED_COUNT, 1)?;
    delta(&pair.a, &a_before, BOUNCES, 4)?;
    delta(&pair.a, &a_before, QUEUE_FULL, 7)?;
    control.close()?;
    bob.close()?;
    pair.stop()
}

#[test]
fn covered_components_exchange_all_presence_types_and_a_remote_iq_request_and_result() -> TestResult
{
    const OTHER: &str = "pubsub.b.test";
    let mut options = options(true);
    options.b_certificate_names.push(OTHER.into());
    options.b_extra_toml = format!(
        "[[components.listeners]]\naddress='127.0.0.1:0'\n[components.domains.'{OTHER}']\nsecret='{SECRET}'"
    );
    let mut pair = start(options)?;
    let addr = pair
        .b
        .s2s_addresses()?
        .first()
        .ok_or("B has no S2S listener")?;
    pair.dns
        .srv(OTHER, &[(0, 0, addr.port(), "component.b.test")]);
    pair.dns.a("component.b.test", Ipv4Addr::LOCALHOST);
    let mut a = ComponentClient::authenticated(&pair.a, DOMAIN, SECRET)?;
    let mut b = ComponentClient::authenticated(&pair.b, OTHER, SECRET)?;
    let before_a = pair.a.scrape_metrics()?;
    let before_b = pair.b.scrape_metrics()?;
    for (i, kind) in [
        "",
        "unavailable",
        "probe",
        "subscribe",
        "subscribed",
        "unsubscribe",
        "unsubscribed",
        "error",
    ]
    .into_iter()
    .enumerate()
    {
        let ty = if kind.is_empty() {
            String::new()
        } else {
            format!(" type='{kind}'")
        };
        let payload = if kind == "error" {
            "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>"
        } else {
            "<status>component presence</status>"
        };
        let xml = format!(
            "<presence xmlns='{NAMESPACE}' xml:lang='en'{ty} from='{ROOM}/nick' to='node@{OTHER}/dest' id='presence-{i}'>{payload}</presence>"
        );
        a.send(&xml)?;
        b.expect_xml(&xml)?;
    }
    let request = format!(
        "<iq xmlns='{NAMESPACE}' xml:lang='en' type='get' from='{ROOM}/nick' to='node@{OTHER}/dest' id='federated'><query xmlns='urn:test:component'/></iq>"
    );
    a.send(&request)?;
    b.expect_xml(&request)?;
    let result = format!(
        "<iq xmlns='{NAMESPACE}' xml:lang='en' type='result' from='node@{OTHER}/dest' to='{ROOM}/nick' id='federated'><answer xmlns='urn:test:component'>verified</answer></iq>"
    );
    b.send(&result)?;
    a.expect_xml(&result)?;
    for (suite, before, component_direction, s2s_direction) in [
        (&pair.a, &before_a, "received", "sent"),
        (&pair.b, &before_b, "sent", "received"),
    ] {
        traffic(
            suite,
            before,
            "component",
            component_direction,
            "presence",
            8,
        )?;
        traffic(suite, before, "s2s", s2s_direction, "presence", 8)?;
        for direction in ["received", "sent"] {
            traffic(suite, before, "component", direction, "iq", 1)?;
            traffic(suite, before, "s2s", direction, "iq", 1)?;
        }
    }
    a.close()?;
    b.close()?;
    pair.stop()
}
