// SPDX-License-Identifier: Apache-2.0

use super::{FederatedPair, PairOptions};
use crate::support::{Client, TestResult, xml::Element};

pub(crate) const ACCOUNTS: (&str, &str, &str, &str) = ("a.test", "alice", "b.test", "bob");

pub(crate) fn workflow_options() -> PairOptions {
    let extensions = "'roster', 'offline', 'carbons', 'disco', 'ping', 'vcard'";
    PairOptions {
        a_extensions: extensions.into(),
        b_extensions: extensions.into(),
        ..PairOptions::default()
    }
}

pub(crate) fn roster(client: &mut Client) -> TestResult<Element> {
    client.send("<iq type='get' id='roster'><query xmlns='jabber:iq:roster'/></iq>")?;
    let reply = client.receive()?;
    reply.assert_name("jabber:client", "iq");
    assert_eq!(reply.attribute("id"), Some("roster"));
    assert_eq!(reply.attribute("type"), Some("result"));
    reply.child("jabber:iq:roster", "query")?;
    Ok(reply)
}

pub(crate) fn push(
    client: &mut Client,
    jid: &str,
    subscription: &str,
    ask: Option<&str>,
) -> TestResult {
    let reply = client.receive()?;
    reply.assert_name("jabber:client", "iq");
    assert_eq!(reply.attribute("type"), Some("set"));
    let query = reply.child("jabber:iq:roster", "query")?;
    assert_eq!(query.children.len(), 1);
    let item = query.child("jabber:iq:roster", "item")?;
    assert_eq!(item.attribute("jid"), Some(jid));
    assert_eq!(item.attribute("subscription"), Some(subscription));
    assert_eq!(item.attribute("ask"), ask);
    client.send(&format!(
        "<iq type='result' id='{}'/>",
        reply.attribute("id").ok_or("missing push ID")?
    ))
}

pub(crate) fn presence(
    client: &mut Client,
    from: &str,
    to: &str,
    kind: Option<&str>,
) -> TestResult<Element> {
    let reply = client.receive()?;
    reply.assert_name("jabber:client", "presence");
    assert_eq!(reply.attribute("from"), Some(from));
    assert_eq!(reply.attribute("to"), Some(to));
    assert_eq!(reply.attribute("type"), kind);
    Ok(reply)
}

pub(crate) fn available(client: &mut Client, bare: &str, resource: &str) -> TestResult {
    client.send("<presence/>")?;
    presence(client, &format!("{bare}/{resource}"), bare, None)?;
    Ok(())
}

pub(crate) fn iq_reply(
    client: &mut Client,
    id: &str,
    kind: &str,
    from: &str,
    to: &str,
) -> TestResult<Element> {
    let reply = client.receive()?;
    reply.assert_name("jabber:client", "iq");
    assert_eq!(reply.attribute("id"), Some(id));
    assert_eq!(reply.attribute("type"), Some(kind));
    assert_eq!(reply.attribute("from"), Some(from));
    assert_eq!(reply.attribute("to"), Some(to));
    Ok(reply)
}

pub(crate) fn stanza_error(reply: &Element, condition: &str) -> TestResult {
    assert_eq!(reply.attribute("type"), Some("error"));
    reply
        .child("jabber:client", "error")?
        .child("urn:ietf:params:xml:ns:xmpp-stanzas", condition)?;
    Ok(())
}

#[expect(
    clippy::disallowed_macros,
    reason = "The test reports the final federation counters."
)]
pub(crate) fn traffic(
    pair: &FederatedPair,
    name: &str,
    a_to_b: [u64; 3],
    b_to_a: [u64; 3],
) -> TestResult {
    for (sender, receiver, counts) in [(&pair.a, &pair.b, a_to_b), (&pair.b, &pair.a, b_to_a)] {
        for (kind, count) in ["message", "iq", "presence"].into_iter().zip(counts) {
            for (suite, event) in [(sender, "sent"), (receiver, "received")] {
                let name = format!("lonewolf_s2s_stanzas_{event}_total{{kind=\"{kind}\"}}");
                suite.wait_for_metrics(&name, |body| {
                    let value = body
                        .lines()
                        .find_map(|line| line.strip_prefix(&name)?.strip_prefix(' '));
                    match value {
                        Some(value) => value.parse::<u64>() == Ok(count),
                        None => count == 0,
                    }
                })?;
            }
        }
        if counts.iter().sum::<u64>() > 0 {
            sender.wait_for_metric(
                "lonewolf_s2s_authentications_total{direction=\"outbound\",outcome=\"success\"} 1",
            )?;
            receiver.wait_for_metric(
                "lonewolf_s2s_authentications_total{direction=\"inbound\",outcome=\"success\"} 1",
            )?;
            receiver
                .wait_for_metric("lonewolf_s2s_connections_accepted_total{listener=\"0\"} 1")?;
            sender.wait_for_metric("lonewolf_s2s_dns_resolutions_total{outcome=\"srv\"} 1")?;
        }
    }
    for suite in [&pair.a, &pair.b] {
        suite.wait_for_metric("lonewolf_s2s_outbound_queued_stanzas 0")?;
        suite.wait_for_metric("lonewolf_s2s_outbound_queued_bytes 0")?;
        let body = suite.scrape_metrics()?;
        for line in body
            .lines()
            .filter(|line| line.starts_with("lonewolf_s2s_"))
        {
            eprintln!("METRIC_LEDGER {name} {} {line}", suite.domain);
        }
    }
    Ok(())
}
