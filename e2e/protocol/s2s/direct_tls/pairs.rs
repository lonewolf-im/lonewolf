// SPDX-License-Identifier: Apache-2.0

use super::super::{available, iq_reply, presence, push, roster};
use super::*;
use crate::support::federation::{FederatedPair, PairOptions};

#[test]
fn direct_tls_both_dialing_directions_preserve_bidi_and_separate_link_accounting() -> TestResult {
    for bidi in [false, true] {
        for reverse in [false, true] {
            let mut pair = FederatedPair::start(
                "a.test",
                "b.test",
                PairOptions {
                    a_bidirectional: Some(bidi),
                    b_bidirectional: Some(bidi),
                    a_extensions: "'ping'".into(),
                    b_extensions: "'ping'".into(),
                    ..PairOptions::default()
                },
            )?;
            pair.direct_tls()?;
            pair.a.create_account("alice", PASSWORD)?;
            pair.b.create_account("bob", PASSWORD)?;
            let mut alice = pair.a.connect("alice", PASSWORD, "desk")?;
            let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
            let (first, second, first_jid, second_jid) = if reverse {
                (
                    &mut bob,
                    &mut alice,
                    "bob@b.test/phone",
                    "alice@a.test/desk",
                )
            } else {
                (
                    &mut alice,
                    &mut bob,
                    "alice@a.test/desk",
                    "bob@b.test/phone",
                )
            };
            first.send(&format!(
                "<message to='{second_jid}' type='chat' id='dial'><body>Dial first</body></message>"
            ))?;
            second.expect_xml(&format!("<message xmlns='jabber:client' from='{first_jid}' to='{second_jid}' type='chat' id='dial' xml:lang='en'><body>Dial first</body></message>"))?;
            second.send(&format!("<message to='{first_jid}' type='chat' id='reverse'><body>Reverse traffic</body></message>"))?;
            first.expect_xml(&format!("<message xmlns='jabber:client' from='{second_jid}' to='{first_jid}' type='chat' id='reverse' xml:lang='en'><body>Reverse traffic</body></message>"))?;
            let second_domain = if reverse { "a.test" } else { "b.test" };
            first.send(&format!("<iq to='{second_domain}' type='get' id='pair-iq'><ping xmlns='urn:xmpp:ping'/></iq>"))?;
            iq_reply(first, "pair-iq", "result", second_domain, first_jid)?;
            for (is_a, suite) in [(true, &pair.a), (false, &pair.b)] {
                let initiates = is_a != reverse;
                let outgoing = !bidi || initiates;
                let incoming = !bidi || !initiates;
                for (direction, active) in [("outbound", outgoing), ("inbound", incoming)] {
                    transport_attempts(
                        suite,
                        direction,
                        if active {
                            &[("direct", "success", 1)]
                        } else {
                            &[]
                        },
                    )?;
                    transport_connections(suite, direction, 0, u64::from(active))?;
                    if active {
                        authentication(suite, direction, "success", 1)?;
                    }
                }
                suite.wait_for_metric(
                    "lonewolf_s2s_listener_info{listener=\"0\",tls_mode=\"direct\"} 1",
                )?;
                suite.wait_for_metric("lonewolf_s2s_outbound_queued_stanzas 0")?;
                suite.wait_for_metric("lonewolf_s2s_outbound_queued_bytes 0")?;
                let remote_domain = if is_a { "b.test" } else { "a.test" };
                for service in ["_xmpp-server", "_xmpps-server"] {
                    assert_eq!(
                        pair.dns.query_count(
                            &format!("{service}._tcp.{remote_domain}"),
                            RecordType::SRV
                        ),
                        usize::from(outgoing)
                    );
                }
            }
            alice.close()?;
            bob.close()?;
            for suite in [&mut pair.a, &mut pair.b] {
                let state = suite
                    .stop_with_s2s_state()?
                    .ok_or("missing shutdown receipt")?;
                assert_eq!(state.queued_stanzas, 0);
                assert_eq!(state.queued_bytes, 0);
                assert_eq!(state.connections, [0; 2]);
                assert_eq!(state.transport_connections, [[0; 2]; 2]);
            }
            pair.dns.stop()?;
        }
    }
    Ok(())
}

#[test]
fn direct_tls_subscriptions_presence_and_correlated_iq_use_one_shared_connection() -> TestResult {
    let mut pair = FederatedPair::start(
        "a.test",
        "b.test",
        PairOptions {
            a_bidirectional: Some(true),
            b_bidirectional: Some(true),
            a_extensions: "'roster', 'ping'".into(),
            b_extensions: "'roster', 'ping'".into(),
            ..PairOptions::default()
        },
    )?;
    pair.direct_tls()?;
    pair.a.create_account("alice", PASSWORD)?;
    pair.b.create_account("bob", PASSWORD)?;
    let mut alice = pair.a.connect("alice", PASSWORD, "desk")?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    alice.send("<message to='bob@b.test/phone' type='chat' id='routing'><body>Direct routing</body></message>")?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@a.test/desk' to='bob@b.test/phone' type='chat' id='routing' xml:lang='en'><body>Direct routing</body></message>")?;
    for client in [&mut alice, &mut bob] {
        assert!(
            roster(client)?
                .child("jabber:iq:roster", "query")?
                .children
                .is_empty()
        );
    }
    available(&mut alice, "alice@a.test", "desk")?;
    available(&mut bob, "bob@b.test", "phone")?;
    bob.send("<iq type='set' id='add-alice'><query xmlns='jabber:iq:roster'><item jid='alice@a.test'/></query></iq>")?;
    bob.expect_xml(
        "<iq xmlns='jabber:client' type='result' id='add-alice' to='bob@b.test/phone'/>",
    )?;
    push(&mut bob, "alice@a.test", "none", None)?;
    bob.send("<presence type='subscribe' to='alice@a.test'/>")?;
    push(&mut bob, "alice@a.test", "none", Some("subscribe"))?;
    presence(&mut alice, "bob@b.test", "alice@a.test", Some("subscribe"))?;
    alice.send("<presence type='subscribed' to='bob@b.test'/>")?;
    push(&mut alice, "bob@b.test", "from", None)?;
    presence(&mut bob, "alice@a.test", "bob@b.test", Some("subscribed"))?;
    push(&mut bob, "alice@a.test", "to", None)?;
    presence(&mut bob, "alice@a.test/desk", "bob@b.test", None)?;
    alice.send("<presence type='subscribe' to='bob@b.test'/>")?;
    push(&mut alice, "bob@b.test", "from", Some("subscribe"))?;
    presence(&mut bob, "alice@a.test", "bob@b.test", Some("subscribe"))?;
    bob.send("<presence type='subscribed' to='alice@a.test'/>")?;
    push(&mut bob, "alice@a.test", "both", None)?;
    presence(&mut alice, "bob@b.test", "alice@a.test", Some("subscribed"))?;
    push(&mut alice, "bob@b.test", "both", None)?;
    presence(&mut alice, "bob@b.test/phone", "alice@a.test", None)?;
    alice.send(
        "<iq type='get' id='subscription-ping' to='bob@b.test'><ping xmlns='urn:xmpp:ping'/></iq>",
    )?;
    iq_reply(
        &mut alice,
        "subscription-ping",
        "result",
        "bob@b.test",
        "alice@a.test/desk",
    )?;
    transport_attempts(&pair.a, "outbound", &[("direct", "success", 1)])?;
    transport_attempts(&pair.b, "inbound", &[("direct", "success", 1)])?;
    transport_attempts(&pair.b, "outbound", &[])?;
    transport_connections(&pair.a, "outbound", 0, 1)?;
    transport_connections(&pair.b, "inbound", 0, 1)?;
    transport_connections(&pair.b, "outbound", 0, 0)?;
    for service in ["_xmpp-server._tcp.a.test", "_xmpps-server._tcp.a.test"] {
        assert_eq!(pair.dns.query_count(service, RecordType::SRV), 0);
    }
    alice.close()?;
    presence(
        &mut bob,
        "alice@a.test/desk",
        "bob@b.test",
        Some("unavailable"),
    )?;
    bob.close()?;
    for suite in [&mut pair.a, &mut pair.b] {
        let state = suite
            .stop_with_s2s_state()?
            .ok_or("missing shutdown receipt")?;
        assert_eq!(state.queued_stanzas, 0);
        assert_eq!(state.queued_bytes, 0);
        assert_eq!(state.connections, [0; 2]);
        assert_eq!(state.transport_connections, [[0; 2]; 2]);
    }
    pair.dns.stop()
}
