// SPDX-License-Identifier: Apache-2.0

use crate::support::federation::workflow::{
    ACCOUNTS, available, iq_reply, presence, stanza_error, traffic, workflow_options,
};
use crate::support::federation::{FederatedPair, subscribe_mutually};
use crate::support::{PASSWORD, TestResult};

const DISCO_INFO: &str = "http://jabber.org/protocol/disco#info";
const DISCO_ITEMS: &str = "http://jabber.org/protocol/disco#items";

#[test]
fn disco_info_of_remote_server() -> TestResult {
    let (ad, an, bd, bn) = ACCOUNTS;
    let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
    pair.a.create_account(an, PASSWORD)?;
    pair.b.create_account(bn, PASSWORD)?;
    let aj = format!("{an}@{ad}");
    let mut a = pair.a.connect(an, PASSWORD, "desk")?;
    let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
    a.send(&format!("<iq type='get' id='disco' to='{bd}'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>"))?;
    let reply = iq_reply(&mut a, "disco", "result", bd, &format!("{aj}/desk"))?;
    let query = reply.child("http://jabber.org/protocol/disco#info", "query")?;
    let identity = query.child("http://jabber.org/protocol/disco#info", "identity")?;
    assert_eq!(identity.attribute("category"), Some("server"));
    assert_eq!(identity.attribute("type"), Some("im"));
    for feature in [
        "jabber:iq:roster",
        "msgoffline",
        "urn:xmpp:carbons:2",
        "urn:xmpp:ping",
        "vcard-temp",
    ] {
        assert!(
            query
                .children
                .iter()
                .any(|child| child.name == "feature" && child.attribute("var") == Some(feature))
        );
    }
    traffic(&pair, "disco_info_of_remote_server", [0, 1, 0], [0, 1, 0])?;
    a.close()?;
    b.close()?;
    pair.stop()?;
    Ok(())
}

#[test]
fn remote_account_discovery_requires_presence_authorization() -> TestResult {
    let (ad, an, bd, bn) = ACCOUNTS;
    let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
    pair.a.create_account(an, PASSWORD)?;
    pair.b.create_account(bn, PASSWORD)?;
    let aj = format!("{an}@{ad}");
    let bj = format!("{bn}@{bd}");
    let phone = format!("{bj}/phone");
    let mut a = pair.a.connect(an, PASSWORD, "desk")?;
    let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
    available(&mut a, &aj, "desk")?;
    b.send(&format!(
        "<iq type='get' id='private-info' to='{aj}'><query xmlns='{DISCO_INFO}'/></iq>"
    ))?;
    stanza_error(
        &iq_reply(&mut b, "private-info", "error", &aj, &phone)?,
        "service-unavailable",
    )?;
    b.send(&format!(
        "<iq type='get' id='private-items' to='{aj}'><query xmlns='{DISCO_ITEMS}'/></iq>"
    ))?;
    let items = iq_reply(&mut b, "private-items", "result", &aj, &phone)?;
    assert!(items.child(DISCO_ITEMS, "query")?.children.is_empty());
    subscribe_mutually(&mut a, &aj, &mut b, &bj)?;
    b.send(&format!(
        "<iq type='get' id='authorized-info' to='{aj}'><query xmlns='{DISCO_INFO}'/></iq>"
    ))?;
    let info = iq_reply(&mut b, "authorized-info", "result", &aj, &phone)?;
    let query = info.child(DISCO_INFO, "query")?;
    let identity = query.child(DISCO_INFO, "identity")?;
    assert_eq!(identity.attribute("category"), Some("account"));
    assert_eq!(identity.attribute("type"), Some("registered"));
    for feature in [DISCO_INFO, DISCO_ITEMS] {
        assert!(
            query
                .children
                .iter()
                .any(|child| child.name == "feature" && child.attribute("var") == Some(feature)),
            "{query:?}"
        );
    }
    b.send(&format!(
        "<iq type='get' id='authorized-items' to='{aj}'><query xmlns='{DISCO_ITEMS}'/></iq>"
    ))?;
    let items = iq_reply(&mut b, "authorized-items", "result", &aj, &phone)?;
    let query = items.child(DISCO_ITEMS, "query")?;
    assert_eq!(query.children.len(), 1, "{query:?}");
    assert_eq!(
        query.child(DISCO_ITEMS, "item")?.attribute("jid"),
        Some(format!("{aj}/desk").as_str())
    );
    traffic(
        &pair,
        "remote_account_discovery_requires_presence_authorization",
        [0, 4, 3],
        [0, 4, 3],
    )?;
    b.close()?;
    presence(&mut a, &phone, &aj, Some("unavailable"))?;
    a.close()?;
    pair.stop()?;
    Ok(())
}
